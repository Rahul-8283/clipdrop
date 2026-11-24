//go:build darwin

package screenshots

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/imaging"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
)

// DefaultPollInterval is the default frequency for sampling the screenshot directory.
const DefaultPollInterval = 250 * time.Millisecond

// ResolveScreencaptureDir resolves the user's configured screenshot destination
// by querying system preferences, falling back to ~/Desktop if unset.
func ResolveScreencaptureDir() (string, error) {
	out, err := exec.Command("defaults", "read", "com.apple.screencapture", "location").Output()
	if err == nil {
		targetDir := strings.TrimSpace(string(out))
		if targetDir != "" {
			if strings.HasPrefix(targetDir, "~/") {
				homeDir, _ := os.UserHomeDir()
				targetDir = filepath.Join(homeDir, targetDir[2:])
			}
			return targetDir, nil
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = os.Getenv("HOME")
	}
	if homeDir == "" {
		return "", errors.New("screenshots: unable to determine user home directory")
	}

	return filepath.Join(homeDir, "Desktop"), nil
}

type fileSample struct {
	size  int64
	count int
}

// Watcher monitors a local directory for newly written screenshots and dispatches
// validated image payloads to the sync engine once file writes have stabilized.
type Watcher struct {
	dir          string
	engine       *engine.Engine
	pollInterval time.Duration
	processed    map[string]int64
	pending      map[string]fileSample
	mu           sync.Mutex
}

// NewWatcher constructs a Watcher for the given directory. If dir is empty,
// it resolves the directory using ResolveScreencaptureDir().
func NewWatcher(dir string, eng *engine.Engine) *Watcher {
	return &Watcher{
		dir:          dir,
		engine:       eng,
		pollInterval: DefaultPollInterval,
		processed:    make(map[string]int64),
		pending:      make(map[string]fileSample),
	}
}

// WithPollInterval configures the directory polling interval (useful for tests).
func (w *Watcher) WithPollInterval(interval time.Duration) *Watcher {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pollInterval = interval
	return w
}

// Dir returns the target directory being monitored.
func (w *Watcher) Dir() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dir
}

// Start begins monitoring the screenshot directory until ctx is cancelled.
func (w *Watcher) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.dir == "" {
		resolved, err := ResolveScreencaptureDir()
		if err != nil {
			w.mu.Unlock()
			return fmt.Errorf("screenshots: resolving directory: %w", err)
		}
		w.dir = resolved
	}
	dir := w.dir
	interval := w.pollInterval
	w.mu.Unlock()

	slog.Info("screenshots: monitoring directory for screenshots", "dir", dir)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.pollOnce()
		}
	}
}

func (w *Watcher) pollOnce() {
	w.mu.Lock()
	defer w.mu.Unlock()

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".png") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if size <= 0 {
			continue
		}

		// Skip if already processed at this exact size
		if w.processed[name] == size {
			continue
		}

		// Debounce stabilization
		sample, exists := w.pending[name]
		if !exists || sample.size != size {
			w.pending[name] = fileSample{size: size, count: 1}
			continue
		}

		sample.count++
		w.pending[name] = sample

		// Debounce requirement: size must remain identical across at least 2 successive polls
		if sample.count >= 2 {
			fullPath := filepath.Join(w.dir, name)
			data, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}

			if _, err := imaging.ValidatePNG(data); err != nil {
				slog.Debug("screenshots: ignoring invalid PNG image", "file", name, "err", err)
				delete(w.pending, name)
				continue
			}

			w.processed[name] = size
			delete(w.pending, name)

			item := &clipboard.Item{
				Kind: clipboard.KindImage,
				Data: data,
				Mime: "image/png",
			}

			slog.Info("screenshots: ingested new screenshot", "file", name, "size", len(data))
			if w.engine != nil {
				w.engine.ProcessItem(item)
			}
		}
	}
}
