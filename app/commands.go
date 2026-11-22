package app

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
)

// Version metadata injected at compile time via -ldflags.
// When building locally without flags, these safe defaults are used.
//
//	-ldflags "-X github.com/Rahul-8283/clipdrop/app.Version=v1.0.0
//	          -X github.com/Rahul-8283/clipdrop/app.Commit=abc1234
//	          -X github.com/Rahul-8283/clipdrop/app.BuildDate=2026-11-19"
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// PrintVersion writes the application version block to stdout.
// Unlike other commands it does not use slog — it prints plain lines
// intended to be read directly by the operator.
//
// Output format:
//
//	clipdrop version dev
//	protocol version 1
//	built with go1.27.4
func PrintVersion() {
	fmt.Printf("clipdrop version %s\n", Version)
	fmt.Printf("protocol version 1\n")
	fmt.Printf("built with %s\n", runtime.Version())
}

// RunSync is the entry point for "clipdrop run".
// It initializes the host clipboard watcher, connects it to the engine,
// and logs local clipboard events in the foreground until cancelled.
func RunSync(ctx context.Context, cfg *config.Config) error {
	clip, err := clipboard.NewReal()
	if err != nil {
		return fmt.Errorf("initializing clipboard: %w", err)
	}

	eng := engine.New(cfg, clip)
	slog.Info("sync: watching clipboard in foreground",
		"images_only", cfg.ImagesOnly,
		"device", cfg.DeviceName,
	)

	// Consume and log outbound events from the engine pipeline
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-eng.Outbound():
				if !ok {
					return
				}
				slog.Info("clipboard event",
					"kind", evt.Item.Kind,
					"size", len(evt.Item.Data),
					"hash", evt.Hash,
				)
			}
		}
	}()

	return eng.Run(ctx)
}

// RunPairHost is the entry point for "clipdrop pair".
// It will start the host-side pairing ceremony in Phase 4.
func RunPairHost(ctx context.Context, cfg *config.Config) error {
	slog.Info("pair: starting host pairing mode (not yet implemented)")
	return nil
}

// RunPairJoin is the entry point for "clipdrop pair join".
// It will start the joiner-side pairing ceremony in Phase 4.
func RunPairJoin(ctx context.Context, cfg *config.Config) error {
	slog.Info("pair join: starting joiner mode (not yet implemented)")
	return nil
}

// RunDevices is the entry point for "clipdrop devices".
// It will list all trusted paired devices in Phase 4.
func RunDevices(ctx context.Context, cfg *config.Config) error {
	slog.Info("devices: listing trusted peers (not yet implemented)")
	return nil
}

// RunUnpair is the entry point for "clipdrop unpair <name>".
// It will revoke trust for a named peer device in Phase 4.
func RunUnpair(ctx context.Context, cfg *config.Config) error {
	slog.Info("unpair: revoking trust (not yet implemented)")
	return nil
}

// RunDoctor is the entry point for "clipdrop doctor".
// It will run system and network diagnostics in Phase 5.
func RunDoctor(ctx context.Context, cfg *config.Config) error {
	slog.Info("doctor: running diagnostics (not yet implemented)")
	return nil
}
