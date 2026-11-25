//go:build !darwin

package screenshots

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/Rahul-8283/clipdrop/engine"
)

// ErrUnsupportedOS is returned when attempting to resolve screencapture on non-macOS platforms.
var ErrUnsupportedOS = errors.New("screenshots: watcher is only supported on macOS")

// ResolveScreencaptureDir returns an error on non-macOS systems.
func ResolveScreencaptureDir() (string, error) {
	return "", ErrUnsupportedOS
}

// Watcher provides a no-op screenshot watcher on unsupported platforms.
type Watcher struct{}

// NewWatcher constructs a no-op Watcher.
func NewWatcher(_ string, _ *engine.Engine) *Watcher {
	return &Watcher{}
}

// WithPollInterval is a no-op on unsupported platforms.
func (w *Watcher) WithPollInterval(_ time.Duration) *Watcher {
	return w
}

// Dir returns empty on unsupported platforms.
func (w *Watcher) Dir() string {
	return ""
}

// Start logs a debug notice and sleeps until ctx is cancelled.
func (w *Watcher) Start(ctx context.Context) error {
	slog.Debug("screenshots: watcher is disabled on non-macOS platforms")
	<-ctx.Done()
	return nil
}
