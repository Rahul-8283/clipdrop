package test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/platform/clipboard"
)

func TestRealClipboard_InitAndInterface(t *testing.T) {
	rc, err := clipboard.NewReal()
	if err != nil {
		if errors.Is(err, clipboard.ErrUnavailable) {
			t.Skip("skipping real clipboard test: host clipboard subsystem unavailable")
		}
		t.Fatalf("unexpected error initializing real clipboard: %v", err)
	}

	// Verify rc satisfies clipboard.Clipboard interface
	var _ clipboard.Clipboard = rc

	// Watch with cancel context should exit cleanly
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch := rc.Watch(ctx)
	// Wait for context cancellation to close the watch channel
	select {
	case _, ok := <-ch:
		if ok {
			// drain
			for range ch {
			}
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Watch did not close after context cancellation")
	}
}
