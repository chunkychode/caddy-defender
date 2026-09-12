package autoblocklist

import (
	"fmt"
	"strings"
	"time"
)

// Config holds the configuration for auto-blocklisting based on HTTP status codes
type Config struct {
	// Enabled determines if auto-blocklisting is active
	Enabled bool `json:"enabled"`

	// StatusCodes defines which HTTP status codes to track (e.g., [404])
	// If empty, ALL requests are tracked regardless of status code
	// Default: [404]
	StatusCodes []int `json:"status_codes,omitempty"`

	// MaxRequests is the maximum number of tracked status codes allowed within the window
	// Default: 10
	MaxRequests int `json:"max_requests,omitempty"`

	// WindowDuration is the time window for counting requests
	// Default: 5m
	WindowDuration time.Duration `json:"window_duration,omitempty"`

	// AutoAddToBlocklist determines if IPs exceeding the limit should be automatically blocked
	// Default: true
	AutoAddToBlocklist bool `json:"auto_add_to_blocklist,omitempty"`

	// CleanupInterval is how often to purge old tracking data
	// Default: 10m
	CleanupInterval time.Duration `json:"cleanup_interval,omitempty"`

	// Paths is a list of request-path signatures that trigger an immediate
	// blocklisting on the first hit, regardless of the response status code.
	// This catches scanners whose probes never produce a tracked status (for
	// example when an auth proxy in front of the app answers every probe with
	// a 302). Matching is case-insensitive:
	//   - entries beginning with "/" are matched as a path prefix
	//     ("/wp-admin" matches "/wp-admin/setup.php")
	//   - all other entries are matched as a substring anywhere in the path
	//     (".env" matches "/aws/.env" and "/.env.bak")
	// Default: none
	Paths []string `json:"paths,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Enabled:            false, // Opt-in feature
		StatusCodes:        []int{404},
		MaxRequests:        10,
		WindowDuration:     5 * time.Minute,
		AutoAddToBlocklist: true,
		CleanupInterval:    10 * time.Minute,
	}
}

// ApplyDefaults fills in any missing configuration values with defaults
func (c *Config) ApplyDefaults() {
	defaults := DefaultConfig()

	// Don't auto-apply status codes - let empty mean "track all"
	// Users must explicitly set to [404] or leave empty for "all"
	// We only apply defaults for other fields
	if c.MaxRequests == 0 {
		c.MaxRequests = defaults.MaxRequests
	}
	if c.WindowDuration == 0 {
		c.WindowDuration = defaults.WindowDuration
	}
	if c.CleanupInterval == 0 {
		c.CleanupInterval = defaults.CleanupInterval
	}
}

// Validate rejects path signatures that are empty or would match every
// request. A lone "/" is the classic footgun: as a prefix it matches all paths
// and would blocklist every visitor on their first request.
func (c Config) Validate() error {
	for i, sig := range c.Paths {
		trimmed := strings.TrimSpace(sig)
		if trimmed == "" {
			return fmt.Errorf("auto_blocklist paths: entry %d is empty", i+1)
		}
		if trimmed != sig {
			return fmt.Errorf("auto_blocklist paths: entry %q has leading/trailing whitespace", sig)
		}
		if sig == "/" {
			return fmt.Errorf("auto_blocklist paths: %q would match every request", sig)
		}
	}
	return nil
}

// MatchPath reports whether the request path hits one of the configured path
// signatures. It returns the matching signature so callers can log it.
// See the Paths field for the matching rules.
func (c Config) MatchPath(path string) (string, bool) {
	if len(c.Paths) == 0 {
		return "", false
	}
	lowered := strings.ToLower(path)
	for _, sig := range c.Paths {
		s := strings.ToLower(sig)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "/") {
			if strings.HasPrefix(lowered, s) {
				return sig, true
			}
			continue
		}
		if strings.Contains(lowered, s) {
			return sig, true
		}
	}
	return "", false
}
