package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
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
// It lists all trusted paired devices or displays onboarding instructions if none exist.
func RunDevices(ctx context.Context, cfg *config.Config) error {
	return RunDevicesTo(ctx, cfg, os.Stdout)
}

// RunDevicesTo outputs the formatted devices table to the specified writer.
func RunDevicesTo(ctx context.Context, cfg *config.Config, out io.Writer) error {
	configDir := cfg.ConfigDir
	if configDir == "" {
		var err error
		configDir, err = config.Dir()
		if err != nil {
			return fmt.Errorf("resolving config directory: %w", err)
		}
	}

	st, err := store.New(filepath.Join(configDir, "trusted_devices.json"))
	if err != nil {
		return fmt.Errorf("loading trusted devices store: %w", err)
	}

	devices := st.List()
	if len(devices) == 0 {
		fmt.Fprintln(out, "No paired devices. Run 'clipdrop pair' to link a peer.")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tOS\tDEVICE ID\tPAIRED\tLAST SEEN\tLAST ADDRESS")

	for _, d := range devices {
		devID := d.ID
		if !cfg.Verbose && len(devID) > 16 {
			devID = devID[:16]
		}

		pairedStr := formatRelativeTime(d.PairedAt)
		lastSeenStr := formatRelativeTime(d.LastSeen)

		lastAddr := d.LastAddress
		if lastAddr == "" {
			lastAddr = "-"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			d.Name,
			d.OS,
			devID,
			pairedStr,
			lastSeenStr,
			lastAddr,
		)
	}

	return w.Flush()
}

// RunUnpair is the entry point for "clipdrop unpair <name>".
// It extracts the target device identifier from os.Args and revokes its trust record.
func RunUnpair(ctx context.Context, cfg *config.Config) error {
	var target string
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "unpair" && i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
			target = os.Args[i+1]
			break
		}
	}
	if target == "" && len(os.Args) >= 3 && !strings.HasPrefix(os.Args[2], "-") {
		target = os.Args[2]
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "error: unpair requires a device name or device ID")
		fmt.Fprintln(os.Stderr, "usage: clipdrop unpair <name>")
		return errors.New("unpair requires a device name or device ID")
	}
	return RunUnpairTarget(ctx, cfg, target)
}

// RunUnpairTarget removes a device identified by name or device ID using standard output streams.
func RunUnpairTarget(ctx context.Context, cfg *config.Config, target string) error {
	return RunUnpairTargetTo(ctx, cfg, target, os.Stdout, os.Stderr)
}

// RunUnpairTargetTo removes a device and writes user-facing messages to the given writers.
func RunUnpairTargetTo(ctx context.Context, cfg *config.Config, target string, out io.Writer, errOut io.Writer) error {
	target = strings.TrimSpace(target)
	if target == "" {
		fmt.Fprintln(errOut, "error: unpair requires a device name or device ID")
		return errors.New("unpair requires a device name or device ID")
	}

	configDir := cfg.ConfigDir
	if configDir == "" {
		var err error
		configDir, err = config.Dir()
		if err != nil {
			return fmt.Errorf("resolving config directory: %w", err)
		}
	}

	st, err := store.New(filepath.Join(configDir, "trusted_devices.json"))
	if err != nil {
		return fmt.Errorf("loading trusted devices store: %w", err)
	}

	devices := st.List()
	normTarget := strings.ToLower(target)

	var matched *store.Device
	for _, d := range devices {
		// Exact match by name or exact match by device ID
		if d.Name == target || strings.EqualFold(d.Name, target) || strings.EqualFold(d.ID, normTarget) {
			matched = d
			break
		}
		// Match by ID prefix (min 8 chars)
		if len(normTarget) >= 8 && strings.HasPrefix(strings.ToLower(d.ID), normTarget) {
			matched = d
			break
		}
	}

	if matched == nil {
		fmt.Fprintf(errOut, "error: device '%s' not found. Run 'clipdrop devices' to list paired devices.\n", target)
		return fmt.Errorf("device '%s' not found", target)
	}

	if err := st.Remove(matched.ID); err != nil {
		return fmt.Errorf("removing device '%s' from store: %w", matched.Name, err)
	}

	truncID := matched.ID
	if len(truncID) > 16 {
		truncID = truncID[:16]
	}

	fmt.Fprintf(out, "Revoked trust for %s (%s).\n", matched.Name, truncID)
	return nil
}

// formatRelativeTime converts timestamps to clean human-readable relative intervals.
func formatRelativeTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	diff := time.Since(t)
	if diff < 0 {
		return t.Format(time.RFC3339)
	}
	switch {
	case diff < 10*time.Second:
		return "just now"
	case diff < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(diff.Seconds()))
	case diff < 2*time.Minute:
		return "1 minute ago"
	case diff < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(diff.Minutes()))
	case diff < 2*time.Hour:
		return "1 hour ago"
	case diff < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(diff.Hours()))
	case diff < 48*time.Hour:
		return "Yesterday"
	case diff < 7*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(diff.Hours()/24))
	default:
		return t.Format(time.RFC3339)
	}
}

// RunDoctor is the entry point for "clipdrop doctor".
// It will run system and network diagnostics in Phase 5.
func RunDoctor(ctx context.Context, cfg *config.Config) error {
	slog.Info("doctor: running diagnostics (not yet implemented)")
	return nil
}
