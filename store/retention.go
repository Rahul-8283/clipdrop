package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Retention limits and directory constants.
const (
	MaxRetainedItems = 20
	ReceivedDirName  = "received"
)

// ErrInvalidDigest is returned when the provided SHA-256 digest is too short or invalid.
var ErrInvalidDigest = errors.New("retention: invalid sha256 digest (must be at least 8 hex characters)")

var (
	safeShaRegex = regexp.MustCompile(`^[a-fA-F0-9]{8,64}$`)
)

// RetentionManager manages the storage and pruning of received clipboard items
// in the <configDir>/received/ directory.
type RetentionManager struct {
	configDir   string
	receivedDir string
	mu          sync.Mutex
}

// NewRetentionManager constructs a RetentionManager for the given config directory.
func NewRetentionManager(configDir string) *RetentionManager {
	return &RetentionManager{
		configDir:   configDir,
		receivedDir: filepath.Join(configDir, ReceivedDirName),
	}
}

// ReceivedDir returns the absolute path to the received items directory.
func (r *RetentionManager) ReceivedDir() string {
	return r.receivedDir
}

// EnsureDir ensures that the received/ directory exists with restricted permissions (0700).
func (r *RetentionManager) EnsureDir() error {
	if err := os.MkdirAll(r.receivedDir, 0700); err != nil {
		return fmt.Errorf("retention: creating received directory: %w", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(r.receivedDir, 0700); err != nil {
			return fmt.Errorf("retention: setting permissions on received directory: %w", err)
		}
	}

	return nil
}

// Archive writes payload data to a timestamped file in <configDir>/received/
// and triggers an asynchronous pruning pass.
func (r *RetentionManager) Archive(kind string, data []byte, sha256Hex string) (string, error) {
	trimmedSha := strings.TrimSpace(sha256Hex)
	if len(trimmedSha) < 8 || !safeShaRegex.MatchString(trimmedSha) {
		return "", fmt.Errorf("%w: got %q", ErrInvalidDigest, sha256Hex)
	}

	if err := r.EnsureDir(); err != nil {
		return "", err
	}

	ext := ".txt"
	if strings.HasPrefix(kind, "image") {
		ext = ".png"
	}

	shortSha := strings.ToLower(trimmedSha[:8])
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	filename := fmt.Sprintf("%s_%s%s", timestamp, shortSha, ext)
	filename = filepath.Base(filename)

	// Strict sanity check against directory traversal
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") || strings.Contains(filename, "..") {
		return "", errors.New("retention: malicious filename detected")
	}

	targetPath := filepath.Join(r.receivedDir, filename)

	// Write atomically via temporary file
	tmpFile, err := os.CreateTemp(r.receivedDir, ".tmp-recv-*")
	if err != nil {
		return "", fmt.Errorf("retention: creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("retention: writing data: %w", err)
	}

	if runtime.GOOS != "windows" {
		_ = tmpFile.Chmod(0600)
	}

	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("retention: closing temp file: %w", err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		return "", fmt.Errorf("retention: committing archived file: %w", err)
	}

	// Trigger non-blocking asynchronous pruning
	go func() {
		_ = r.Prune()
	}()

	return targetPath, nil
}

type fileEntry struct {
	name    string
	modTime time.Time
}

// Prune inspects <configDir>/received/ and deletes the oldest files
// until at most MaxRetainedItems (20) remain.
func (r *RetentionManager) Prune() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entries, err := os.ReadDir(r.receivedDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("retention: reading received directory: %w", err)
	}

	var files []fileEntry
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, fileEntry{
			name:    entry.Name(),
			modTime: info.ModTime(),
		})
	}

	if len(files) <= MaxRetainedItems {
		return nil
	}

	// Sort chronologically: oldest first
	sort.Slice(files, func(i, j int) bool {
		if files[i].modTime.Equal(files[j].modTime) {
			return files[i].name < files[j].name
		}
		return files[i].modTime.Before(files[j].modTime)
	})

	excess := len(files) - MaxRetainedItems
	var firstErr error
	for i := 0; i < excess; i++ {
		filePath := filepath.Join(r.receivedDir, files[i].name)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
