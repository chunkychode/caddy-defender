package caddydefender

import (
	"fmt"
	"net"
	"net/http"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"pkg.jsn.cam/caddy-defender/autoblocklist"
)

// serveIgnore is a helper function to serve a robots.txt file if the ServeIgnore option is enabled.
// It returns true if the request was handled, false otherwise.
func (m Defender) serveGitignore(w http.ResponseWriter, r *http.Request) bool {
	m.log.Debug("ServeIgnore",
		zap.Bool("serveIgnore", m.ServeIgnore),
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
	)

	// Serve robots.txt only if ServeIgnore is enabled, the path is "/robots.txt", and the method is GET.
	if !m.ServeIgnore || r.URL.Path != "/robots.txt" || r.Method != http.MethodGet {
		return false
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	// Build the robots.txt content to allow specific bots and block others.
	robotsTxt := `
User-agent: Googlebot
Disallow:

User-agent: Bingbot
Disallow:

User-agent: DuckDuckBot
Disallow:

User-agent: *
Disallow: /
`
	_, _ = w.Write([]byte(robotsTxt))
	return true
}

// ServeHTTP implements the middleware logic.
func (m Defender) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if m.serveGitignore(w, r) {
		return nil
	}
	// Split the RemoteAddr into IP and port
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.log.Error("Invalid client IP format", zap.String("ip", r.RemoteAddr))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid client IP format"))
	}

	clientIP := net.ParseIP(host)
	if clientIP == nil {
		m.log.Error("Invalid client IP", zap.String("ip", host))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid client IP"))
	}
	m.log.Debug("Ranges", zap.Strings("ranges", m.Ranges))

	// Check if the client IP should be allowed (considering whitelist and blocked ranges)
	if !m.ipChecker.ReqAllowed(r.Context(), clientIP) {
		m.log.Debug("Request blocked (IP in blocked ranges and not whitelisted)", zap.String("ip", clientIP.String()))
		// Request should be blocked
		return m.responder.ServeHTTP(w, r, next)
	}

	m.log.Debug("Request allowed (IP whitelisted or not in blocked ranges)", zap.String("ip", clientIP.String()))

	// Capture the auto-blocklist tracker tracker pointer once to avoid race conditions
	// If we check twice, the limiter could be stopped between checks causing nil pointer panic
	globalAutoBlocklistMu.RLock()
	tracker := globalAutoBlocklist
	globalAutoBlocklistMu.RUnlock()

	// Wrap response writer to capture status code for auto-blocklisting
	var recorder *autoblocklist.ResponseRecorder
	if tracker != nil {
		recorder = autoblocklist.NewResponseRecorder(w)
		w = recorder
	}

	// IP is allowed, proceed to the next handler
	err = next.ServeHTTP(w, r)

	// Track the request for auto-blocklisting if enabled
	// Skip auto-blocklisting for whitelisted IPs
	if tracker != nil && recorder != nil && !m.ipChecker.IsWhitelisted(clientIP) {
		exceeded, trackErr := tracker.TrackRequest(clientIP, recorder.StatusCode)
		if trackErr != nil {
			m.log.Error("Failed to track request for auto-blocklisting",
				zap.String("ip", clientIP.String()),
				zap.Error(trackErr))
		}

		// If threshold exceeded, add IP to blocklist
		if exceeded && m.AutoBlocklistConfig.AutoAddToBlocklist {
			if addErr := m.addIPToBlocklist(clientIP); addErr != nil {
				m.log.Error("Failed to add IP to blocklist",
					zap.String("ip", clientIP.String()),
					zap.Error(addErr))
			} else {
				m.log.Info("Threshold exceeded - IP added to blocklist",
					zap.String("ip", clientIP.String()),
					zap.String("blocklist_file", m.BlocklistFile),
					zap.Int("status_code", recorder.StatusCode),
					zap.Int("max_requests", m.AutoBlocklistConfig.MaxRequests),
					zap.Duration("window", m.AutoBlocklistConfig.WindowDuration))

				// Block this request immediately (Option A)
				return m.responder.ServeHTTP(recorder.ResponseWriter, r, next)
			}
		}
	} else if tracker != nil && recorder != nil {
		m.log.Debug("Skipping auto-blocklisting for whitelisted IP",
			zap.String("ip", clientIP.String()))
	}

	return err
}

// addIPToBlocklist adds an IP address to the blocklist file (if configured)
func (m *Defender) addIPToBlocklist(clientIP net.IP) error {
	if m.BlocklistFile == "" {
		return fmt.Errorf("blocklist_file not configured")
	}

	// Convert IP to CIDR format
	ipCIDR := fmt.Sprintf("%s/32", clientIP.String())
	if clientIP.To4() == nil {
		// IPv6
		ipCIDR = fmt.Sprintf("%s/128", clientIP.String())
	}

	// Use the DefenderAdmin's addIPsToFile method
	globalAdminMu.RLock()
	admin := globalDefenderAdmin
	globalAdminMu.RUnlock()

	if admin == nil {
		return fmt.Errorf("DefenderAdmin not available")
	}

	return admin.addIPsToFile(m.BlocklistFile, []string{ipCIDR})
}
