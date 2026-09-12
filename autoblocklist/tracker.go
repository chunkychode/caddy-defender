package autoblocklist

import (
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Tracker manages auto-blocklisting based on HTTP status codes per IP address
type Tracker struct {
	config   Config
	storage  map[string]*RequestWindow
	mu       sync.RWMutex
	log      *zap.Logger
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// RequestWindow tracks requests within a time window using a fixed window counter
type RequestWindow struct {
	Count       int
	WindowStart time.Time
	// Blocked is set once the window's count has first crossed MaxRequests.
	// Subsequent requests in the same window still increment Count for stats
	// but TrackRequest returns exceeded=false so callers don't re-fire the
	// "add to blocklist" side effect on every request.
	Blocked bool
}

// NewTracker creates a new auto-blocklist tracker
func NewTracker(config Config, log *zap.Logger) *Tracker {
	config.ApplyDefaults()

	t := &Tracker{
		config:   config,
		storage:  make(map[string]*RequestWindow),
		log:      log,
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	t.wg.Add(1)
	go t.cleanupLoop()

	trackingMode := "specific status codes"
	if len(config.StatusCodes) == 0 {
		trackingMode = "ALL requests"
	}

	t.log.Info("Auto-blocklist tracker initialized",
		zap.Bool("enabled", config.Enabled),
		zap.String("tracking_mode", trackingMode),
		zap.Ints("status_codes", config.StatusCodes),
		zap.Int("max_requests", config.MaxRequests),
		zap.Duration("window_duration", config.WindowDuration),
		zap.Strings("paths", config.Paths))

	return t
}

// TrackRequest tracks a request and returns true if the threshold was exceeded
// This should be called AFTER the request has been processed to know the status code
// If StatusCodes is empty, ALL requests are tracked regardless of status code
func (t *Tracker) TrackRequest(clientIP net.IP, statusCode int) (exceeded bool, err error) {
	if !t.config.Enabled {
		return false, nil
	}

	// If StatusCodes is empty, track all requests
	// Otherwise, check if this status code should be tracked
	if len(t.config.StatusCodes) > 0 && !t.shouldTrackStatus(statusCode) {
		return false, nil
	}

	ipStr := clientIP.String()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Get or create window for this IP
	window, exists := t.storage[ipStr]
	if !exists {
		window = &RequestWindow{
			Count:       1,
			WindowStart: now,
		}
		t.storage[ipStr] = window
		t.log.Debug("Started tracking IP",
			zap.String("ip", ipStr),
			zap.Int("status_code", statusCode))
		return false, nil
	}

	// Check if we need to reset the window
	if now.Sub(window.WindowStart) >= t.config.WindowDuration {
		window.Count = 1
		window.WindowStart = now
		window.Blocked = false
		t.log.Debug("Reset window for IP",
			zap.String("ip", ipStr),
			zap.Int("status_code", statusCode))
		return false, nil
	}

	// Increment counter
	window.Count++

	// Check if limit exceeded. Only fire exceeded=true on the transition
	// from "under" to "over" within a window. Further requests still bump
	// Count for observability but don't re-trigger the caller's block
	// action (prevents thundering-herd blocklist writes).
	if window.Count > t.config.MaxRequests {
		if !window.Blocked {
			window.Blocked = true
			t.log.Warn("Threshold exceeded",
				zap.String("ip", ipStr),
				zap.Int("count", window.Count),
				zap.Int("max", t.config.MaxRequests),
				zap.Duration("window", t.config.WindowDuration),
				zap.Int("status_code", statusCode))
			return true, nil
		}
		t.log.Debug("Threshold still exceeded (already blocklisted)",
			zap.String("ip", ipStr),
			zap.Int("count", window.Count),
			zap.Int("status_code", statusCode))
		return false, nil
	}

	t.log.Debug("Tracked request",
		zap.String("ip", ipStr),
		zap.Int("count", window.Count),
		zap.Int("max", t.config.MaxRequests),
		zap.Int("status_code", statusCode))

	return false, nil
}

// Config returns the effective configuration (defaults applied) that this
// tracker was built with. Because the tracker is a process-wide singleton,
// callers should consult this rather than their own instance's config when
// deciding what to do on a threshold hit.
func (t *Tracker) Config() Config {
	return t.config
}

// MatchPath reports whether the request path hits a configured path signature.
func (t *Tracker) MatchPath(path string) (string, bool) {
	return t.config.MatchPath(path)
}

// MarkBlocked records that the IP was blocklisted outside the normal
// status-code counting (e.g. via a path-signature hit). The IP's window is
// forced over the threshold so that stats report it and a later status-code
// transition does not fire a duplicate "add to blocklist" action.
func (t *Tracker) MarkBlocked(clientIP net.IP) {
	ipStr := clientIP.String()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	window, exists := t.storage[ipStr]
	if !exists || now.Sub(window.WindowStart) >= t.config.WindowDuration {
		window = &RequestWindow{WindowStart: now}
		t.storage[ipStr] = window
	}
	if window.Count <= t.config.MaxRequests {
		window.Count = t.config.MaxRequests + 1
	}
	window.Blocked = true
}

// shouldTrackStatus checks if a status code should be tracked
func (t *Tracker) shouldTrackStatus(statusCode int) bool {
	for _, code := range t.config.StatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

// GetStats returns current tracking statistics
func (t *Tracker) GetStats() map[string]TrackedIP {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := make(map[string]TrackedIP, len(t.storage))
	now := time.Now()

	for ip, window := range t.storage {
		stats[ip] = TrackedIP{
			IP:               ip,
			RequestCount:     window.Count,
			WindowStart:      window.WindowStart,
			TimeRemaining:    t.config.WindowDuration - now.Sub(window.WindowStart),
			ExceedsThreshold: window.Count > t.config.MaxRequests,
		}
	}

	return stats
}

// TrackedIP represents statistics for a single IP address
type TrackedIP struct {
	IP               string        `json:"ip"`
	RequestCount     int           `json:"request_count"`
	WindowStart      time.Time     `json:"window_start"`
	TimeRemaining    time.Duration `json:"time_remaining"`
	ExceedsThreshold bool          `json:"exceeds_threshold"`
}

// cleanupLoop periodically removes old tracking entries
func (t *Tracker) cleanupLoop() {
	defer t.wg.Done()

	ticker := time.NewTicker(t.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.cleanup()
		case <-t.stopChan:
			return
		}
	}
}

// cleanup removes entries older than 2x the window duration
func (t *Tracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	cutoff := t.config.WindowDuration * 2
	removed := 0

	for ip, window := range t.storage {
		if now.Sub(window.WindowStart) > cutoff {
			delete(t.storage, ip)
			removed++
		}
	}

	if removed > 0 {
		t.log.Debug("Cleaned up old tracking entries",
			zap.Int("removed", removed),
			zap.Int("remaining", len(t.storage)))
	}
}

// Stop gracefully shuts down the tracker
func (t *Tracker) Stop() {
	close(t.stopChan)
	t.wg.Wait()
	t.log.Info("Auto-blocklist tracker stopped")
}

// ResetIP clears tracking data for a specific IP
func (t *Tracker) ResetIP(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.storage[ip]; exists {
		delete(t.storage, ip)
		t.log.Info("Reset auto-blocklist tracking for IP", zap.String("ip", ip))
		return true
	}
	return false
}
