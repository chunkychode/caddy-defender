package fetchers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// FileFetcher implements IPRangeFetcher for loading IP addresses from a file.
// It supports automatic reloading when the file changes.
type FileFetcher struct {
	watcher  *fsnotify.Watcher
	log      *zap.Logger
	onChange func([]string) // Callback when ranges are updated
	ranges   []string
	mu       sync.RWMutex
	filePath string
}

// NewFileFetcher creates a new FileFetcher with file watching capability
func NewFileFetcher(filePath string, log *zap.Logger, onChange func([]string)) (*FileFetcher, error) {
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	f := &FileFetcher{
		filePath: filePath,
		watcher:  watcher,
		log:      log,
		onChange: onChange,
	}

	// Initial load
	if err := f.loadRanges(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to load initial ranges: %w", err)
	}

	// Start watching the file
	if err := f.startWatching(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to start watching file: %w", err)
	}

	return f, nil
}

// Name returns the name identifier for this fetcher
func (f *FileFetcher) Name() string {
	return "file"
}

// Description returns a description of this fetcher
func (f *FileFetcher) Description() string {
	return fmt.Sprintf("IP ranges loaded from file: %s", f.filePath)
}

// FetchIPRanges returns the current IP ranges loaded from the file.
//
// An empty result is a valid state: the file may be missing on a fresh
// deployment, present-but-empty, or contain only comments. The directory
// watcher will pick up later writes.
func (f *FileFetcher) FetchIPRanges() ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]string, len(f.ranges))
	copy(result, f.ranges)
	return result, nil
}

// loadRanges reads IP addresses/ranges from the file.
//
// A missing file is tolerated: new deployments commonly ship without a
// blocklist, and we expect the parent-directory watcher to pick up the
// eventual CREATE event. In that case we simply install an empty range set.
func (f *FileFetcher) loadRanges() error {
	file, err := os.Open(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			f.mu.Lock()
			f.ranges = nil
			f.mu.Unlock()
			f.log.Info("Blocklist file does not yet exist; starting with empty range set",
				zap.String("file", f.filePath))
			return nil
		}
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var ranges []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate the IP/CIDR format
		if err := f.validateIPOrCIDR(line); err != nil {
			f.log.Warn("Invalid IP/CIDR in file",
				zap.String("file", f.filePath),
				zap.Int("line", lineNum),
				zap.String("value", line),
				zap.Error(err))
			continue
		}

		ranges = append(ranges, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	f.mu.Lock()
	f.ranges = ranges
	f.mu.Unlock()

	f.log.Info("Loaded IP ranges from file",
		zap.String("file", f.filePath),
		zap.Int("count", len(ranges)))

	return nil
}

// validateIPOrCIDR validates that the string is either a valid IP address or CIDR range
func (f *FileFetcher) validateIPOrCIDR(s string) error {
	// Try parsing as CIDR first
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}

	// Try parsing as IP address
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}

	return fmt.Errorf("invalid IP address or CIDR range: %q", s)
}

// startWatching begins monitoring the file for changes.
//
// We watch the parent directory instead of the file itself so that atomic
// writes (write-to-tmp + rename) don't leave us watching a stale inode. Events
// for unrelated files in the directory are filtered out in watchLoop.
func (f *FileFetcher) startWatching() error {
	dir := filepath.Dir(f.filePath)
	if err := f.watcher.Add(dir); err != nil {
		return fmt.Errorf("failed to watch directory: %w", err)
	}

	go f.watchLoop()
	f.log.Info("Started watching file for changes",
		zap.String("file", f.filePath),
		zap.String("watching_dir", dir))

	return nil
}

// watchLoop handles file change events
func (f *FileFetcher) watchLoop() {
	// Resolve the target path once so we can compare against event.Name.
	// Both are passed through filepath.Clean so comparisons work regardless
	// of how the user spelled the configured path.
	target := filepath.Clean(f.filePath)

	for {
		select {
		case event, ok := <-f.watcher.Events:
			if !ok {
				return
			}

			if filepath.Clean(event.Name) != target {
				continue
			}

			// Reload on write, create, or rename (atomic writes land as RENAME).
			relevant := fsnotify.Write | fsnotify.Create | fsnotify.Rename
			if event.Op&relevant == 0 {
				continue
			}

			f.log.Info("File changed, reloading IP ranges",
				zap.String("file", f.filePath),
				zap.String("event", event.Op.String()))

			if err := f.loadRanges(); err != nil {
				f.log.Error("Failed to reload IP ranges",
					zap.String("file", f.filePath),
					zap.Error(err))
				continue
			}

			if f.onChange != nil {
				f.mu.RLock()
				rangesCopy := make([]string, len(f.ranges))
				copy(rangesCopy, f.ranges)
				f.mu.RUnlock()

				f.onChange(rangesCopy)
			}

		case err, ok := <-f.watcher.Errors:
			if !ok {
				return
			}
			f.log.Error("File watcher error",
				zap.String("file", f.filePath),
				zap.Error(err))
		}
	}
}

// Close stops watching the file and cleans up resources
func (f *FileFetcher) Close() error {
	if f.watcher != nil {
		return f.watcher.Close()
	}
	return nil
}
