package caddydefender

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestAdmin builds a DefenderAdmin wired with a no-op logger; the file I/O
// helpers don't read any other fields.
func newTestAdmin() *DefenderAdmin {
	return &DefenderAdmin{log: zap.NewNop()}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	raw := strings.Split(string(data), "\n")
	// Trailing newline produces an empty final element; drop it.
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	return raw
}

func TestAddIPsToFile_PreservesCommentsAndOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	initial := "# banned 2026-04-01 — SSRF attempt\n" +
		"10.0.0.1/32\n" +
		"\n" +
		"# operators team\n" +
		"10.0.0.2/32\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0644))

	admin := newTestAdmin()
	require.NoError(t, admin.addIPsToFile(path, []string{"10.0.0.99/32"}))

	lines := readLines(t, path)
	assert.Equal(t, []string{
		"# banned 2026-04-01 — SSRF attempt",
		"10.0.0.1/32",
		"",
		"# operators team",
		"10.0.0.2/32",
		"10.0.0.99/32",
	}, lines)
}

func TestAddIPsToFile_DedupesAgainstExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")
	require.NoError(t, os.WriteFile(path, []byte("10.0.0.1/32\n"), 0644))

	admin := newTestAdmin()
	require.NoError(t, admin.addIPsToFile(path, []string{"10.0.0.1/32", "10.0.0.2/32"}))
	// Second call with the same inputs must be a no-op.
	require.NoError(t, admin.addIPsToFile(path, []string{"10.0.0.1/32", "10.0.0.2/32"}))

	lines := readLines(t, path)
	assert.Equal(t, []string{"10.0.0.1/32", "10.0.0.2/32"}, lines)
}

func TestAddIPsToFile_CreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	admin := newTestAdmin()
	require.NoError(t, admin.addIPsToFile(path, []string{"10.0.0.1/32"}))

	lines := readLines(t, path)
	assert.Equal(t, []string{"10.0.0.1/32"}, lines)
}

func TestRemoveIPFromFile_PreservesComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	initial := "# banned 2026-04-01 — SSRF attempt\n" +
		"10.0.0.1/32\n" +
		"# keep me\n" +
		"10.0.0.2/32\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0644))

	admin := newTestAdmin()
	removed, err := admin.removeIPFromFile(path, "10.0.0.1/32")
	require.NoError(t, err)
	assert.True(t, removed)

	lines := readLines(t, path)
	assert.Equal(t, []string{
		"# banned 2026-04-01 — SSRF attempt",
		"# keep me",
		"10.0.0.2/32",
	}, lines)
}

func TestRemoveIPFromFile_MissingFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.txt")

	admin := newTestAdmin()
	removed, err := admin.removeIPFromFile(path, "10.0.0.1/32")
	require.NoError(t, err)
	assert.False(t, removed)
}

func TestWriteBlocklistAtomic_PreservesExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission modes are not meaningfully preserved on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	require.NoError(t, os.WriteFile(path, []byte("10.0.0.1/32\n"), 0640))
	require.NoError(t, os.Chmod(path, 0640)) // WriteFile obeys umask; enforce.

	require.NoError(t, writeBlocklistAtomic(path, []string{"10.0.0.1/32", "10.0.0.2/32"}))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0640), info.Mode().Perm(),
		"rewrite must carry the original mode so peer processes keep access")
}

func TestWriteBlocklistAtomic_NewFileIsPeerReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission modes are not meaningfully preserved on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	require.NoError(t, writeBlocklistAtomic(path, []string{"10.0.0.1/32"}))

	info, err := os.Stat(path)
	require.NoError(t, err)
	// The actual behavioural guarantee: a peer process (non-owner) can read
	// the file. os.CreateTemp's 0600 would fail this; the helper must
	// override to a peer-readable mode for fresh files.
	assert.NotZero(t, info.Mode().Perm()&0004,
		"world-read bit must be set on a newly-created blocklist, got %v", info.Mode().Perm())
}
