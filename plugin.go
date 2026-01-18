package caddydefender

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"pkg.jsn.cam/caddy-defender/matchers/ip"
	"pkg.jsn.cam/caddy-defender/ranges/fetchers"
	"pkg.jsn.cam/caddy-defender/ratelimit"
	"pkg.jsn.cam/caddy-defender/responders"
	"pkg.jsn.cam/caddy-defender/responders/tarpit"
)

func init() {
	// Register the module with Caddy
	caddy.RegisterModule(Defender{})
	httpcaddyfile.RegisterHandlerDirective("defender", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("defender", "after", "header")
}

var (
	// DefaultRanges is the default ranges to block if none are specified.
	DefaultRanges = []string{"aws", "gcloud", "azurepubliccloud", "openai", "deepseek", "githubcopilot"}
	// Tarpit Defaults
	// defaultTarpitTimeout is the default duration for a request to be closed after.
	defaultTarpitTimeout = time.Second * 30
	// defaultTarpitBytesPerSecond is the default amount of bytes to stream per second.
	defaultTarpitBytesPerSecond = 24
	// defaultTarpitResponseCode is the default HTTP respond code for the tarpit responder.
	defaultTarpitResponseCode = http.StatusOK

	// globalRateLimiter is the singleton rate limiter instance shared across all Defender instances
	globalRateLimiter         *ratelimit.Tracker
	globalRateLimiterMu       sync.RWMutex
	globalRateLimiterRefCount int              // Tracks how many Defender instances are using the rate limiter
	globalRateLimiterConfig   *ratelimit.Config // Stores the config from the first instance for comparison
)

// Defender implements an HTTP middleware that enforces IP-based rules to protect your site from AIs/Scrapers.
// It allows blocking or manipulating requests based on client IP addresses using CIDR ranges or predefined ranges
// for services such as AWS, GCP, OpenAI, and GitHub Copilot.
//
// **JSON Configuration:**
//
// ```json
//
//	{
//	  "handler": "defender",
//	  "raw_responder": "block",
//	  "ranges": ["openai", "10.0.0.0/8"],
//	  "message": "Custom block message" // Only for 'custom' responder
//	}
//
// ```
//
// **Caddyfile Syntax:**
// ```
//
//	defender <responder_type> {
//	    ranges <cidr_or_predefined...>
//	    message <custom_message>
//	}
//
// ```
//
// Supported responder types:
// - `block`: Immediately block requests with 403 Forbidden
// - `custom`: Return a custom message (requires `message` field)
// - `drop`: Drops the connection
// - `garbage`: Respond with random garbage data
// - `redirect`: Redirect requests to a URL with 308 permanent redirect
// - `tarpit`: Stream data at a slow, but configurable rate to stall bots and pollute AI training
//
// For built-in rate limiting based on status codes, see the `rate_limit_config` option.
//
// For a list of predefined ranges, see the [readme]
// [readme]: https://github.com/JasonLovesDoggo/caddy-defender#embedded-ip-ranges
type Defender struct {
	// responder is the internal implementation of the response strategy
	responder responders.Responder
	ipChecker *ip.IPChecker
	log       *zap.Logger
	// fileFetcher is the internal file watcher for dynamic IP loading
	fileFetcher interface{ Close() error }

	// Message specifies the custom response message for 'custom' responder type.
	// Required when using 'custom' responder.
	Message string `json:"message,omitempty"`

	// StatusCode specifies the HTTP status code for 'custom' responder type.
	// Optional. Default: 200
	StatusCode int `json:"status_code,omitempty"`

	// URL specifies the custom URL to redirect clients to for 'redirect' responder type.
	// Required only when using 'redirect' responder.
	URL string `json:"url,omitempty"`

	// RawResponder defines the response strategy for blocked requests.
	// Required. Must be one of: "block", "custom", "drop", "garbage", "redirect", "tarpit"
	RawResponder string `json:"raw_responder,omitempty"`

	// Ranges specifies IP ranges to block, which can be either:
	// - CIDR notations (e.g., "192.168.1.0/24")
	// - Predefined service keys (e.g., "openai", "aws")
	// Default:
	Ranges []string `json:"ranges,omitempty"`

	// An optional whitelist of IP addresses to exclude from blocking. If empty, no IPs are whitelisted.
	// NOTE: this only supports IP addresses, not ranges.
	// Default: []
	Whitelist []string `json:"whitelist,omitempty"`

	// An optional configuration for the 'tarpit' responder
	// Default: {Headers: {}, timeout: 30s, ResponseCode: 200}
	TarpitConfig tarpit.Config `json:"tarpit_config,omitempty"`

	// BlocklistFile specifies a path to a file containing IP addresses/ranges to block (one per line).
	// The file is monitored for changes and automatically reloaded.
	// Lines starting with # are treated as comments and empty lines are ignored.
	// Default: ""
	BlocklistFile string `json:"blocklist_file,omitempty"`

	// ServeIgnore specifies whether to serve a robots.txt file with a "Disallow: /" directive
	// Default: false
	ServeIgnore bool `json:"serve_ignore,omitempty"`

	// RateLimitConfig configures automatic blocking based on HTTP status codes (e.g., 404s)
	// When enabled, IPs exceeding the threshold are automatically added to the blocklist
	// Default: disabled
	// NOTE: Rate limiting is global across all Defender instances
	RateLimitConfig ratelimit.Config `json:"rate_limit_config,omitempty"`
}

// Provision sets up the middleware, logger, and responder configurations.
func (m *Defender) Provision(ctx caddy.Context) error {
	m.log = ctx.Logger(m)

	if len(m.Ranges) == 0 {
		// set the default ranges to be all of the predefined ranges
		m.log.Debug("no ranges specified, defaulting to default ranges", zap.Strings("ranges", DefaultRanges))
		m.Ranges = DefaultRanges
	}

	// Try to register this Defender instance with the global admin API module
	// This happens after admin apps are provisioned, so we use a global variable
	globalAdminMu.RLock()
	if globalDefenderAdmin != nil {
		globalDefenderAdmin.RegisterDefender(m)
		m.log.Info("Registered with DefenderAdmin API")
	} else {
		m.log.Debug("DefenderAdmin not available - admin API endpoints will not be available")
	}
	globalAdminMu.RUnlock()

	// ensure to keep AFTER the ranges are checked (above)
	m.ipChecker = ip.NewIPChecker(m.Ranges, m.Whitelist, m.log)

	// Set up file-based IP range loading if a blocklist file is specified
	if m.BlocklistFile != "" {
		fileFetcher, err := fetchers.NewFileFetcher(m.BlocklistFile, m.log, func(newRanges []string) {
			// Callback when file changes - merge with configured ranges
			allRanges := append([]string{}, m.Ranges...)
			allRanges = append(allRanges, newRanges...)
			m.ipChecker.UpdateRanges(allRanges)
		})
		if err != nil {
			return fmt.Errorf("failed to initialize blocklist file watcher: %w", err)
		}
		m.fileFetcher = fileFetcher

		// Load initial ranges from file and merge with configured ranges
		fileRanges, err := fileFetcher.FetchIPRanges()
		if err != nil {
			fileFetcher.Close()
			return fmt.Errorf("failed to load initial blocklist file: %w", err)
		}

		// Merge file ranges with configured ranges
		allRanges := append([]string{}, m.Ranges...)
		allRanges = append(allRanges, fileRanges...)
		m.ipChecker.UpdateRanges(allRanges)

		m.log.Info("Blocklist file monitoring enabled",
			zap.String("file", m.BlocklistFile),
			zap.Int("initial_count", len(fileRanges)))
	}

	// Finish configuring tarpit responder's content reader / defaults
	if m.RawResponder == "tarpit" {
		tarpitResponder, ok := m.responder.(*tarpit.Responder)
		if !ok {
			return fmt.Errorf("expected tarpit responder but got %T", m.responder)
		}

		err := tarpitResponder.ConfigureContentReader()
		if err != nil {
			return err
		}

		if m.TarpitConfig.Timeout == 0 {
			m.TarpitConfig.Timeout = defaultTarpitTimeout
		}

		if m.TarpitConfig.BytesPerSecond == 0 {
			m.TarpitConfig.BytesPerSecond = defaultTarpitBytesPerSecond
		}

		if m.TarpitConfig.ResponseCode == 0 {
			m.TarpitConfig.ResponseCode = defaultTarpitResponseCode
		}
	}

	// Initialize global rate limiter if enabled and not already initialized
	// This is shared across ALL Defender instances for global rate limiting
	if m.RateLimitConfig.Enabled {
		globalRateLimiterMu.Lock()
		if globalRateLimiter == nil {
			// First instance - initialize the rate limiter
			globalRateLimiter = ratelimit.NewTracker(m.RateLimitConfig, m.log)
			globalRateLimiterConfig = &m.RateLimitConfig
			m.log.Info("Global rate limiter initialized (singleton)",
				zap.Ints("status_codes", m.RateLimitConfig.StatusCodes),
				zap.Int("max_requests", m.RateLimitConfig.MaxRequests),
				zap.Duration("window", m.RateLimitConfig.WindowDuration))
		} else {
			// Subsequent instance - check if config matches
			m.log.Info("Using existing global rate limiter instance")
			if !configsMatch(globalRateLimiterConfig, &m.RateLimitConfig) {
				m.log.Warn("Rate limiter config differs from first instance - using first instance's config",
					zap.Ints("first_status_codes", globalRateLimiterConfig.StatusCodes),
					zap.Int("first_max_requests", globalRateLimiterConfig.MaxRequests),
					zap.Duration("first_window", globalRateLimiterConfig.WindowDuration),
					zap.Ints("this_status_codes", m.RateLimitConfig.StatusCodes),
					zap.Int("this_max_requests", m.RateLimitConfig.MaxRequests),
					zap.Duration("this_window", m.RateLimitConfig.WindowDuration))
			}
		}
		globalRateLimiterRefCount++
		m.log.Debug("Rate limiter reference count incremented",
			zap.Int("ref_count", globalRateLimiterRefCount))
		globalRateLimiterMu.Unlock()
	}

	return nil
}

// configsMatch compares two rate limit configs to check if they're equivalent
func configsMatch(c1, c2 *ratelimit.Config) bool {
	if c1 == nil || c2 == nil {
		return c1 == c2
	}

	// Compare basic fields
	if c1.MaxRequests != c2.MaxRequests ||
		c1.WindowDuration != c2.WindowDuration ||
		c1.AutoAddToBlocklist != c2.AutoAddToBlocklist ||
		c1.CleanupInterval != c2.CleanupInterval {
		return false
	}

	// Compare status code slices
	if len(c1.StatusCodes) != len(c2.StatusCodes) {
		return false
	}
	// Create a map for easier comparison
	statusMap := make(map[int]bool)
	for _, code := range c1.StatusCodes {
		statusMap[code] = true
	}
	for _, code := range c2.StatusCodes {
		if !statusMap[code] {
			return false
		}
	}

	return true
}

// CaddyModule returns the Caddy module information.
func (Defender) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.defender",
		New: func() caddy.Module { return new(Defender) },
	}
}

// Cleanup closes the file watcher and decrements the rate limiter reference count
func (m *Defender) Cleanup() error {
	if m.fileFetcher != nil {
		if err := m.fileFetcher.Close(); err != nil {
			return err
		}
	}

	// Decrement global rate limiter reference count and stop it when last instance cleans up
	if m.RateLimitConfig.Enabled {
		globalRateLimiterMu.Lock()
		globalRateLimiterRefCount--
		m.log.Debug("Rate limiter reference count decremented",
			zap.Int("ref_count", globalRateLimiterRefCount))

		// Stop the rate limiter when the last instance is cleaned up
		if globalRateLimiterRefCount <= 0 && globalRateLimiter != nil {
			m.log.Info("Stopping global rate limiter (last instance cleaned up)")
			globalRateLimiter.Stop()
			globalRateLimiter = nil
			globalRateLimiterConfig = nil
			globalRateLimiterRefCount = 0 // Ensure it doesn't go negative
		}
		globalRateLimiterMu.Unlock()
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Defender)(nil)
	_ caddy.CleanerUpper          = (*Defender)(nil)
	_ caddyhttp.MiddlewareHandler = (*Defender)(nil)
	_ caddyfile.Unmarshaler       = (*Defender)(nil)
)
