// Package app wires application components together and manages the
// process lifecycle including OS signal handling and graceful shutdown.
package app

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
)

// shutdownTimeout is the maximum time granted to in-flight work to drain
// cleanly after a termination signal is received before a forced return.
const shutdownTimeout = 3 * time.Second

// App owns the root application configuration and coordinates the
// lifecycle of all long-running components.
type App struct {
	cfg *config.Config
}

// New constructs an App from the provided configuration pointer.
func New(cfg *config.Config) *App {
	return &App{cfg: cfg}
}

// Run wires the application lifecycle around the provided handler:
//
//  1. A signal-aware child context is derived from ctx. It cancels on
//     SIGINT (Ctrl+C) or SIGTERM from the operating system, or whenever
//     the parent ctx is cancelled.
//  2. The handler is launched in a background goroutine and receives the
//     signal-aware context so it can respond to cancellation.
//  3. If the handler returns before any signal arrives, Run propagates its
//     return value immediately — no drain timer is started.
//  4. If a signal (or parent cancellation) arrives first, shutdown() emits
//     a notice and a 3-second drain timer begins. Run then waits for the
//     handler to finish. If the handler does not finish within the budget,
//     Run logs a warning and returns nil so the process can exit.
func (a *App) Run(ctx context.Context, handler func(context.Context) error) error {
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Buffer size 1 ensures the goroutine never blocks on send even if
	// Run has already returned (e.g. after the drain timeout).
	errCh := make(chan error, 1)
	go func() {
		errCh <- handler(sigCtx)
	}()

	select {
	case err := <-errCh:
		// Handler completed on its own before any signal arrived.
		return err

	case <-sigCtx.Done():
		// OS signal or parent context cancellation received.
		a.shutdown()

		drainTimer := time.NewTimer(shutdownTimeout)
		defer drainTimer.Stop()

		select {
		case err := <-errCh:
			// Handler drained cleanly within the allotted budget.
			return err
		case <-drainTimer.C:
			slog.Warn("app: shutdown timed out, forcing exit",
				"timeout", shutdownTimeout,
			)
			return nil
		}
	}
}

// shutdown logs the shutdown notice. It is called exactly once when a
// termination signal is received, before the drain timer is started.
func (a *App) shutdown() {
	slog.Info("app: shutting down...")
}
