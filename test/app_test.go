package test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/app"
	"github.com/Rahul-8283/clipdrop/config"
)

// newTestApp is a helper that builds an *app.App using default config.
func newTestApp() *app.App {
	cfg := config.Defaults()
	return app.New(&cfg)
}

// TestRun_CallsHandlerExactlyOnce verifies that Run invokes the handler
// exactly one time, never zero or more than one.
func TestRun_CallsHandlerExactlyOnce(t *testing.T) {
	a := newTestApp()

	var callCount atomic.Int32

	err := a.Run(context.Background(), func(_ context.Context) error {
		callCount.Add(1)
		return nil
	})

	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if n := callCount.Load(); n != 1 {
		t.Errorf("handler called %d time(s); want exactly 1", n)
	}
}

// TestRun_PropagatesHandlerError verifies that an error returned by the
// handler is returned unchanged by Run.
func TestRun_PropagatesHandlerError(t *testing.T) {
	a := newTestApp()
	want := errors.New("handler failed")

	got := a.Run(context.Background(), func(_ context.Context) error {
		return want
	})

	if !errors.Is(got, want) {
		t.Errorf("Run() error = %v; want %v", got, want)
	}
}

// TestRun_NilOnSuccess verifies Run returns nil when the handler
// returns nil.
func TestRun_NilOnSuccess(t *testing.T) {
	a := newTestApp()

	err := a.Run(context.Background(), func(_ context.Context) error {
		return nil
	})
	if err != nil {
		t.Errorf("Run() = %v; want nil", err)
	}
}

// TestRun_CancelledContextReturnsPromptly verifies that cancelling the
// parent context causes Run to return in well under the 3-second drain
// budget. We use a 2-second hard deadline as the test guard.
func TestRun_CancelledContextReturnsPromptly(t *testing.T) {
	a := newTestApp()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run even starts

	done := make(chan error, 1)
	go func() {
		done <- a.Run(ctx, func(ctx context.Context) error {
			// Simulate a well-behaved handler that respects context cancellation.
			<-ctx.Done()
			return nil
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return promptly after context cancellation (waited 2s)")
	}
}

// TestRun_HandlerReceivesCancellation verifies that the context passed
// to the handler is cancelled when the parent context is cancelled,
// confirming the signal-forwarding chain is wired correctly.
func TestRun_HandlerReceivesCancellation(t *testing.T) {
	a := newTestApp()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var ctxCancelledInHandler bool

	_ = a.Run(ctx, func(handlerCtx context.Context) error {
		select {
		case <-handlerCtx.Done():
			ctxCancelledInHandler = true
			return nil
		case <-time.After(2 * time.Second):
			return errors.New("handler never received cancellation")
		}
	})

	if !ctxCancelledInHandler {
		t.Error("handler's context was never cancelled when parent context expired")
	}
}
