package caddydefender

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

var (
	// globalDefenderAdmin holds the singleton instance
	globalDefenderAdmin *DefenderAdmin
	globalAdminMu       sync.RWMutex
)

// IPRangeFetcher defines the interface for fetching IP ranges from a source
type IPRangeFetcher interface {
	FetchIPRanges() ([]string, error)
}

func init() {
	caddy.RegisterModule(&DefenderAdmin{})
}

// DefenderAdmin is an App module that provides admin API routes for managing Defender
type DefenderAdmin struct {
	ctx caddy.Context
	log *zap.Logger

	defender *Defender
	mu       sync.RWMutex

	// fileMu serializes writes to blocklist files so concurrent callers
	// (admin API + rate-limit auto-add) cannot race on os.Rename/os.Create.
	fileMu sync.Mutex
}

// CaddyModule returns the Caddy module information
func (*DefenderAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.defender",
		New: func() caddy.Module { return new(DefenderAdmin) },
	}
}

// Provision sets up the DefenderAdmin module
func (d *DefenderAdmin) Provision(ctx caddy.Context) error {
	d.ctx = ctx
	d.log = ctx.Logger(d)

	// Set the global instance so Defender middleware can register
	globalAdminMu.Lock()
	globalDefenderAdmin = d
	globalAdminMu.Unlock()

	d.log.Info("DefenderAdmin provisioned - admin API routes will be available")

	return nil
}

// Start is called after all modules are provisioned
func (d *DefenderAdmin) Start() error {
	d.mu.RLock()
	hasDefender := d.defender != nil
	d.mu.RUnlock()

	d.log.Info("DefenderAdmin started", zap.Bool("defender_registered", hasDefender))
	return nil
}

// Stop is called when the app is shutting down
func (d *DefenderAdmin) Stop() error {
	// Clear the global instance
	globalAdminMu.Lock()
	globalDefenderAdmin = nil
	globalAdminMu.Unlock()

	d.log.Info("DefenderAdmin stopped")
	return nil
}

// RegisterDefender allows a Defender middleware instance to register itself
func (d *DefenderAdmin) RegisterDefender(defender *Defender) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.defender = defender
	d.log.Debug("Registered Defender instance")
}

// UnregisterDefender removes the Defender instance from the registry
func (d *DefenderAdmin) UnregisterDefender() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.defender = nil
	d.log.Debug("Unregistered Defender instance")
}

// getDefender retrieves the registered Defender instance
func (d *DefenderAdmin) getDefender() *Defender {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.defender
}

// Routes implements caddy.AdminRouter to add API endpoints
func (d *DefenderAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/defender/blocklist",
			Handler: caddy.AdminHandlerFunc(d.handleBlocklist),
		},
		{
			// Trailing slash = ServeMux subtree match (e.g. /defender/blocklist/1.2.3.4).
			// A "/*" suffix would be a literal, not a wildcard, and never match.
			Pattern: "/defender/blocklist/",
			Handler: caddy.AdminHandlerFunc(d.handleBlocklistItem),
		},
		{
			Pattern: "/defender/stats",
			Handler: caddy.AdminHandlerFunc(d.handleStats),
		},
		{
			Pattern: "/defender/auto_blocklist/stats",
			Handler: caddy.AdminHandlerFunc(d.handleAutoBlocklistStats),
		},
		{
			// Trailing slash = ServeMux subtree match (e.g. /defender/auto_blocklist/reset/1.2.3.4).
			Pattern: "/defender/auto_blocklist/reset/",
			Handler: caddy.AdminHandlerFunc(d.handleAutoBlocklistReset),
		},
	}
}

// handleBlocklist handles GET and POST for /defender/blocklist
func (d *DefenderAdmin) handleBlocklist(w http.ResponseWriter, r *http.Request) error {
	defender := d.getDefender()
	if defender == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "no defender instances available",
		}
	}

	switch r.Method {
	case http.MethodGet:
		return d.handleGetBlocklist(w, defender)
	case http.MethodPost:
		return d.handleAddToBlocklist(w, r, defender)
	default:
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}
}

// handleGetBlocklist returns all blocked IPs from the blocklist file
func (d *DefenderAdmin) handleGetBlocklist(w http.ResponseWriter, m *Defender) error {
	if m.BlocklistFile == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "blocklist_file must be configured to use the Admin API",
		}
	}

	fileFetcher, ok := m.fileFetcher.(IPRangeFetcher)
	if !ok {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    "file fetcher not available",
		}
	}

	ips, err := fileFetcher.FetchIPRanges()
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to read blocklist file: %v", err),
		}
	}

	response := map[string]interface{}{
		"total": len(ips),
		"ips":   ips,
		"file":  m.BlocklistFile,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// handleAddToBlocklist adds IPs to the blocklist file
func (d *DefenderAdmin) handleAddToBlocklist(w http.ResponseWriter, r *http.Request, m *Defender) error {
	if m.BlocklistFile == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "blocklist_file must be configured to use the Admin API",
		}
	}

	var req struct {
		IPs []string `json:"ips"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid JSON: %v", err),
		}
	}

	if len(req.IPs) == 0 {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "no IPs provided",
		}
	}

	// Validate IPs are in CIDR format and check against whitelist
	var whitelistedIPs []string
	for _, ipCIDR := range req.IPs {
		if !strings.Contains(ipCIDR, "/") {
			return caddy.APIError{
				HTTPStatus: http.StatusBadRequest,
				Message:    fmt.Sprintf("IP must be in CIDR format (e.g., %s/32): %s", ipCIDR, ipCIDR),
			}
		}

		// Extract the IP address from CIDR (e.g., "192.168.1.1/32" -> "192.168.1.1")
		ipStr := strings.Split(ipCIDR, "/")[0]
		clientIP := net.ParseIP(ipStr)
		if clientIP != nil && m.ipChecker.IsWhitelisted(clientIP) {
			whitelistedIPs = append(whitelistedIPs, ipCIDR)
		}
	}

	// Reject the request if any IPs are whitelisted
	if len(whitelistedIPs) > 0 {
		return caddy.APIError{
			HTTPStatus: http.StatusForbidden,
			Message:    fmt.Sprintf("cannot add whitelisted IPs to blocklist: %v", whitelistedIPs),
		}
	}

	// Add IPs to the file directly
	if err := d.addIPsToFile(m.BlocklistFile, req.IPs); err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to add IPs to blocklist file: %v", err),
		}
	}

	// File watcher will automatically detect the change and update IPChecker

	response := map[string]interface{}{
		"added": req.IPs,
		"count": len(req.IPs),
		"file":  m.BlocklistFile,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(response)
}

// handleBlocklistItem handles DELETE for /defender/blocklist/{ip}
func (d *DefenderAdmin) handleBlocklistItem(w http.ResponseWriter, r *http.Request) error {
	defender := d.getDefender()
	if defender == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "no defender instances available",
		}
	}

	if r.Method != http.MethodDelete {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	if defender.BlocklistFile == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "blocklist_file must be configured to use the Admin API",
		}
	}

	// Extract IP from path (remove "/defender/blocklist/" prefix)
	path := strings.TrimPrefix(r.URL.Path, "/defender/blocklist/")
	ip := strings.TrimSpace(path)

	if ip == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "IP address required",
		}
	}

	// Remove IP from file
	removed, err := d.removeIPFromFile(defender.BlocklistFile, ip)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to remove IP from blocklist file: %v", err),
		}
	}
	if !removed {
		return caddy.APIError{
			HTTPStatus: http.StatusNotFound,
			Message:    fmt.Sprintf("IP not found in blocklist: %s", ip),
		}
	}

	// File watcher will automatically detect the change and update IPChecker

	response := map[string]interface{}{
		"removed": ip,
		"file":    defender.BlocklistFile,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// handleStats returns statistics about blocked requests
func (d *DefenderAdmin) handleStats(w http.ResponseWriter, r *http.Request) error {
	defender := d.getDefender()
	if defender == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "no defender instances available",
		}
	}

	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	fileCount := 0
	if defender.BlocklistFile != "" {
		fileFetcher, ok := defender.fileFetcher.(IPRangeFetcher)
		if ok {
			fileRanges, _ := fileFetcher.FetchIPRanges()
			fileCount = len(fileRanges)
		}
	}

	response := map[string]interface{}{
		"configured_ranges": defender.Ranges,
		"blocklist_file":    defender.BlocklistFile,
		"counts": map[string]int{
			"configured_ranges": len(defender.Ranges),
			"file_ranges":       fileCount,
			"total":             len(defender.Ranges) + fileCount,
		},
		"responder": defender.RawResponder,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// defaultBlocklistMode is the permission mode applied to a newly-created
// blocklist file. Peer processes (backup, fail2ban, log tooling) commonly run
// under a different UID and need read access, so we default to world-readable.
const defaultBlocklistMode os.FileMode = 0644

// addIPsToFile ensures the given IPs are present in the blocklist file.
//
// The file's original contents (comments, blank lines, and existing order) are
// preserved verbatim; new entries are appended at the bottom. Entries that are
// already present are silent no-ops. A missing file is treated as a fresh
// deploy and is created on the first write.
func (d *DefenderAdmin) addIPsToFile(filePath string, ips []string) error {
	d.fileMu.Lock()
	defer d.fileMu.Unlock()

	existing := make(map[string]struct{})
	var lines []string

	file, err := os.Open(filePath)
	switch {
	case err == nil:
		defer file.Close()
		scanner := bufio.NewScanner(file)
		// Raise the per-line limit so an unusually long comment doesn't
		// silently truncate the scan.
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			raw := scanner.Text()
			lines = append(lines, raw)
			trimmed := strings.TrimSpace(raw)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				existing[trimmed] = struct{}{}
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read blocklist file: %w", err)
		}
	case os.IsNotExist(err):
		// Fresh deploy: no file yet. Fall through and create it.
	default:
		return fmt.Errorf("failed to open blocklist file: %w", err)
	}

	added := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, ok := existing[ip]; ok {
			continue
		}
		existing[ip] = struct{}{}
		lines = append(lines, ip)
		added = append(added, ip)
	}

	if len(added) == 0 {
		return nil
	}

	if err := writeBlocklistAtomic(filePath, lines); err != nil {
		return err
	}

	d.log.Info("Added IPs to blocklist file",
		zap.String("file", filePath),
		zap.Strings("ips", added))

	return nil
}

// writeBlocklistAtomic writes the given lines to filePath atomically: write to
// a sibling temp file, fsync, chmod to match the existing file's mode, then
// rename over the target. This prevents the file watcher from observing a
// half-written file and preserves peer-process read access across rewrites.
//
// Lines are written verbatim (no modification, one per line). Cleanup of the
// temp file is deferred so a panic or future early return cannot leak it.
func writeBlocklistAtomic(filePath string, lines []string) (retErr error) {
	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, filepath.Base(filePath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmp.Name()

	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		// After a successful Rename the temp name no longer points at a file;
		// the Remove returns ENOENT and is harmless. On any failure path, the
		// temp file is cleaned up here rather than left behind.
		_ = os.Remove(tmpName)
	}()

	writer := bufio.NewWriter(tmp)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("failed to write line: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to fsync temp file: %w", err)
	}

	// Match the permission mode of the existing file so peer processes keep
	// their access after rewrite. os.CreateTemp produces 0600, which would
	// otherwise silently lock out a non-owner reader on the first rewrite.
	mode := defaultBlocklistMode
	if info, err := os.Stat(filePath); err == nil {
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat target: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	closed = true

	if err := os.Rename(tmpName, filePath); err != nil {
		return fmt.Errorf("failed to rename temp file into place: %w", err)
	}
	return nil
}

// removeIPFromFile removes an IP from the blocklist file, preserving all
// surrounding lines (comments, blanks, other IPs) verbatim. Returns
// (found=false, nil) if the IP isn't present, or if the file doesn't exist.
func (d *DefenderAdmin) removeIPFromFile(filePath string, ipToRemove string) (bool, error) {
	d.fileMu.Lock()
	defer d.fileMu.Unlock()

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to open blocklist file: %w", err)
	}
	defer file.Close()

	// The blocklist stores entries in CIDR form (e.g. "9.9.9.9/32"), but the
	// DELETE API receives a bare IP from the URL path. Match a bare IP against
	// its host-CIDR forms too, while still allowing an exact CIDR to be passed.
	target := strings.TrimSpace(ipToRemove)
	matches := func(line string) bool {
		return line == target || line == target+"/32" || line == target+"/128"
	}

	var lines []string
	found := false
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Text()
		if matches(strings.TrimSpace(raw)) {
			found = true
			continue
		}
		lines = append(lines, raw)
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to read blocklist file: %w", err)
	}

	if !found {
		return false, nil
	}

	if err := writeBlocklistAtomic(filePath, lines); err != nil {
		return false, err
	}

	d.log.Info("Removed IP from blocklist file",
		zap.String("file", filePath),
		zap.String("ip", ipToRemove))

	return true, nil
}

// handleAutoBlocklistStats returns current auto-blocklisting statistics
func (d *DefenderAdmin) handleAutoBlocklistStats(w http.ResponseWriter, r *http.Request) error {
	defender := d.getDefender()
	if defender == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "no defender instances available",
		}
	}

	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	// Access the global auto-blocklist tracker (singleton)
	globalAutoBlocklistMu.RLock()
	tracker := globalAutoBlocklist
	globalAutoBlocklistMu.RUnlock()

	if tracker == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "auto-blocklisting not enabled",
		}
	}

	stats := tracker.GetStats()

	response := map[string]interface{}{
		"enabled":       defender.AutoBlocklistConfig.Enabled,
		"status_codes":  defender.AutoBlocklistConfig.StatusCodes,
		"max_requests":  defender.AutoBlocklistConfig.MaxRequests,
		"window":        defender.AutoBlocklistConfig.WindowDuration.String(),
		"tracked_count": len(stats),
		"tracked_ips":   stats,
		"note":          "Auto-blocklisting is global across all Defender instances",
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// handleAutoBlocklistReset resets auto-blocklisting tracking for a specific IP
func (d *DefenderAdmin) handleAutoBlocklistReset(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodDelete {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	// Access the global auto-blocklist tracker (singleton)
	globalAutoBlocklistMu.RLock()
	tracker := globalAutoBlocklist
	globalAutoBlocklistMu.RUnlock()

	if tracker == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "auto-blocklisting not enabled",
		}
	}

	// Extract IP from path
	path := strings.TrimPrefix(r.URL.Path, "/defender/auto_blocklist/reset/")
	ip := strings.TrimSpace(path)

	if ip == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "IP address required",
		}
	}

	reset := tracker.ResetIP(ip)
	if !reset {
		return caddy.APIError{
			HTTPStatus: http.StatusNotFound,
			Message:    fmt.Sprintf("IP not found in auto-blocklist tracking: %s", ip),
		}
	}

	response := map[string]interface{}{
		"reset": ip,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// Interface guards
var (
	_ caddy.Module      = (*DefenderAdmin)(nil)
	_ caddy.Provisioner = (*DefenderAdmin)(nil)
	_ caddy.App         = (*DefenderAdmin)(nil)
	_ caddy.AdminRouter = (*DefenderAdmin)(nil)
)
