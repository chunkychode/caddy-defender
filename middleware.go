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

	clientIP, err := clientIPFromRequest(r)
	if err != nil {
		m.log.Error("Invalid client IP", zap.String("remote_addr", r.RemoteAddr), zap.Error(err))
		return caddyhttp.Error(http.StatusForbidden, err)
	}
	m.log.Debug("Ranges", zap.Strings("ranges", m.Ranges))

	// Check if the client IP should be allowed (considering whitelist and blocked ranges)
	if !m.ipChecker.ReqAllowed(r.Context(), clientIP) {
		m.log.Debug("Request blocked (IP in blocked ranges and not whitelisted)", zap.String("ip", clientIP.String()))
		// Request should be blocked
		return m.responder.ServeHTTP(w, r, next)
	}

	m.log.Debug("Request allowed (IP whitelisted or not in blocked ranges)", zap.String("ip", clientIP.String()))

	// Snapshot the global tracker once. If we read it twice, Cleanup could
	// stop it between reads and we would dereference nil.
	tracker, fallbackFile := currentAutoBlocklist()
	if tracker == nil {
		return next.ServeHTTP(w, r)
	}

	// Whitelisted IPs are never auto-blocklisted.
	if m.ipChecker.IsWhitelisted(clientIP) {
		m.log.Debug("Skipping auto-blocklisting for whitelisted IP",
			zap.String("ip", clientIP.String()))
		return next.ServeHTTP(w, r)
	}

	// The tracker is a singleton, so its config (not this instance's) decides
	// whether a violation is written to the blocklist. Otherwise a vhost
	// without an auto_blocklist block would consume the once-per-window
	// "exceeded" transition and the IP would never be written by anyone.
	autoAdd := tracker.Config().AutoAddToBlocklist

	// Path signatures: ban on first sight, before the request reaches the app.
	// Status-code counting is useless behind an auth proxy that answers every
	// probe with a 302, so this is the primary defence for those vhosts.
	if sig, hit := tracker.MatchPath(r.URL.Path); hit {
		tracker.MarkBlocked(clientIP)
		if !autoAdd {
			m.log.Warn("Path signature hit (detect-only, auto_add_to_blocklist disabled)",
				zap.String("ip", clientIP.String()),
				zap.String("path", r.URL.Path),
				zap.String("signature", sig))
			return next.ServeHTTP(w, r)
		}
		if addErr := m.addIPToBlocklist(clientIP, fallbackFile); addErr != nil {
			m.log.Error("Failed to add IP to blocklist after path signature hit",
				zap.String("ip", clientIP.String()),
				zap.String("path", r.URL.Path),
				zap.Error(addErr))
			return next.ServeHTTP(w, r)
		}
		m.log.Warn("Path signature hit - IP added to blocklist",
			zap.String("ip", clientIP.String()),
			zap.String("path", r.URL.Path),
			zap.String("signature", sig),
			zap.String("host", r.Host))
		return m.responder.ServeHTTP(w, r, next)
	}

	// Wrap response writer to capture status code for auto-blocklisting
	recorder := autoblocklist.NewResponseRecorder(w)

	// IP is allowed, proceed to the next handler
	err = next.ServeHTTP(recorder, r)

	exceeded, trackErr := tracker.TrackRequest(clientIP, recorder.StatusCode)
	if trackErr != nil {
		m.log.Error("Failed to track request for auto-blocklisting",
			zap.String("ip", clientIP.String()),
			zap.Error(trackErr))
	}

	// If threshold exceeded, add IP to blocklist
	if exceeded && autoAdd {
		cfg := tracker.Config()
		if addErr := m.addIPToBlocklist(clientIP, fallbackFile); addErr != nil {
			m.log.Error("Failed to add IP to blocklist",
				zap.String("ip", clientIP.String()),
				zap.Error(addErr))
		} else {
			m.log.Info("Threshold exceeded - IP added to blocklist",
				zap.String("ip", clientIP.String()),
				zap.String("host", r.Host),
				zap.Int("status_code", recorder.StatusCode),
				zap.Int("max_requests", cfg.MaxRequests),
				zap.Duration("window", cfg.WindowDuration))

			// Block this request immediately (Option A)
			return m.responder.ServeHTTP(recorder.ResponseWriter, r, next)
		}
	}

	return err
}

// addIPToBlocklist adds an IP address to this instance's blocklist file, or to
// fallbackFile (the global auto-blocklist file) when this instance has none.
func (m *Defender) addIPToBlocklist(clientIP net.IP, fallbackFile string) error {
	file := m.BlocklistFile
	if file == "" {
		file = fallbackFile
	}
	if file == "" {
		return fmt.Errorf("blocklist_file not configured on this or any auto_blocklist-enabled defender")
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

	return admin.addIPsToFile(file, []string{ipCIDR})
}

func clientIPFromRequest(r *http.Request) (net.IP, error) {
	if clientIP, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && clientIP != "" {
		return parseClientIP(clientIP)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid client IP format")
	}
	return parseClientIP(host)
}

func parseClientIP(rawIP string) (net.IP, error) {
	clientIP := net.ParseIP(rawIP)
	if clientIP == nil {
		return nil, fmt.Errorf("invalid client IP")
	}
	return clientIP, nil
}
