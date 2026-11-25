package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/doctor"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/discovery"
	"github.com/Rahul-8283/clipdrop/netx/pairing"
	"github.com/Rahul-8283/clipdrop/store"
	"github.com/grandcat/zeroconf"
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
// It initializes and executes the unified clipboard synchronization pipeline.
func RunSync(ctx context.Context, cfg *config.Config) error {
	pipeline, err := NewSyncPipeline(cfg, nil)
	if err != nil {
		return fmt.Errorf("initializing sync pipeline: %w", err)
	}
	return pipeline.Run(ctx)
}

// RunPairHost is the entry point for "clipdrop pair".
// It generates a pairing code, announces presence on mDNS with status=pairing,
// displays the code banner, and waits for a peer to complete the PAKE ceremony.
func RunPairHost(ctx context.Context, cfg *config.Config) error {
	return RunPairHostTo(ctx, cfg, os.Stdout, nil)
}

// RunPairHostTo starts the pairing host with custom output and optional listener.
func RunPairHostTo(ctx context.Context, cfg *config.Config, out io.Writer, listener net.Listener) error {
	configDir := cfg.ConfigDir
	if configDir == "" {
		var err error
		configDir, err = config.Dir()
		if err != nil {
			return fmt.Errorf("resolving config directory: %w", err)
		}
	}

	ident, err := identity.LoadOrGenerate(configDir, cfg.DeviceName)
	if err != nil {
		return fmt.Errorf("loading device identity: %w", err)
	}

	st, err := store.New(filepath.Join(configDir, "trusted_devices.json"))
	if err != nil {
		return fmt.Errorf("loading trusted devices store: %w", err)
	}

	code, err := pairing.GenerateCode()
	if err != nil {
		return fmt.Errorf("generating pairing code: %w", err)
	}

	var host *pairing.Host
	if listener != nil {
		host, err = pairing.NewHostWithListener(code, ident, st, listener)
	} else {
		host, err = pairing.NewHost(code, ident, st)
	}
	if err != nil {
		return fmt.Errorf("starting pairing server: %w", err)
	}
	defer host.Close()

	// Announce pairing state via mDNS
	announcer, annErr := discovery.Announce(ctx, ident, host.Port(), discovery.StatusPairing)
	if announcer != nil {
		defer announcer.Shutdown()
	}
	if annErr != nil {
		slog.Debug("mdns pairing announcement unavailable", "err", annErr)
	}

	// Print pairing banner
	fmt.Fprintln(out, "==================================================")
	fmt.Fprintf(out, "  Pairing Code:  %s\n", code)
	fmt.Fprintln(out, "  Expires in:    2 minutes")
	fmt.Fprintln(out, "  Waiting for peer to join...")
	fmt.Fprintln(out, "==================================================")

	dev, err := host.Serve(ctx)
	if err != nil {
		return err
	}

	slog.Info("Paired with " + dev.Name)
	fmt.Fprintf(out, "Paired with %s\n", dev.Name)
	return nil
}

// RunPairJoin is the entry point for "clipdrop pair join".
// It acquires the pairing code, discovers the host, and completes the PAKE handshake.
func RunPairJoin(ctx context.Context, cfg *config.Config) error {
	return RunPairJoinWithStreams(ctx, cfg, os.Stdin, os.Stdout, nil)
}

// RunPairJoinWithStreams executes the joiner flow with custom I/O and optional http.Client.
func RunPairJoinWithStreams(ctx context.Context, cfg *config.Config, in io.Reader, out io.Writer, client *http.Client) error {
	configDir := cfg.ConfigDir
	if configDir == "" {
		var err error
		configDir, err = config.Dir()
		if err != nil {
			return fmt.Errorf("resolving config directory: %w", err)
		}
	}

	ident, err := identity.LoadOrGenerate(configDir, cfg.DeviceName)
	if err != nil {
		return fmt.Errorf("loading device identity: %w", err)
	}

	st, err := store.New(filepath.Join(configDir, "trusted_devices.json"))
	if err != nil {
		return fmt.Errorf("loading trusted devices store: %w", err)
	}

	// 1. Determine code from CLI argument or prompt operator
	var code string
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "join" && i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
			code = os.Args[i+1]
			break
		}
	}

	if code == "" && in != nil {
		fmt.Fprint(out, "Enter pairing code: ")
		scanner := bufio.NewScanner(in)
		if scanner.Scan() {
			code = strings.TrimSpace(scanner.Text())
		}
	}

	normCode := pairing.NormalizeCode(code)
	if normCode == "" {
		return errors.New("pairing code is required")
	}

	// 2. Discover host address
	hostAddr := strings.TrimSpace(cfg.PeerAddr)
	if hostAddr == "" {
		fmt.Fprintln(out, "Searching local network for pairing host...")
		var err error
		hostAddr, err = discoverPairingHost(ctx)
		if err != nil {
			return err
		}
	}

	// 3. Perform PAKE handshake and AES-GCM credential swap
	var dev *store.Device
	if client != nil {
		dev, err = pairing.JoinWithHTTPClient(ctx, hostAddr, normCode, ident, st, client)
	} else {
		dev, err = pairing.Join(ctx, hostAddr, normCode, ident, st)
	}

	if err != nil {
		return fmt.Errorf("pairing failed: %w", err)
	}

	slog.Info("Paired with " + dev.Name)
	fmt.Fprintf(out, "Paired with %s\n", dev.Name)
	return nil
}

func discoverPairingHost(ctx context.Context) (string, error) {
	res, err := zeroconf.NewResolver(nil)
	if err != nil {
		return "", fmt.Errorf("creating discovery resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry, 16)
	browseCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	go func() {
		_ = res.Browse(browseCtx, discovery.ServiceType, discovery.Domain, entries)
	}()

	for {
		select {
		case <-browseCtx.Done():
			return "", errors.New("discovery: timed out looking for pairing host (is 'clipdrop pair' running on host?)")
		case entry, ok := <-entries:
			if !ok {
				return "", errors.New("discovery: no pairing hosts found on local network")
			}
			rec := discovery.ParseTXT(entry.Text)
			if rec.Status == discovery.StatusPairing {
				var ip net.IP
				if len(entry.AddrIPv4) > 0 {
					ip = entry.AddrIPv4[0]
				} else if len(entry.AddrIPv6) > 0 {
					ip = entry.AddrIPv6[0]
				}
				if ip != nil {
					return fmt.Sprintf("%s:%d", ip.String(), entry.Port), nil
				}
			}
		}
	}
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
// It executes system and network diagnostics, prints a formatted health report to stdout,
// and returns an error if any critical check fails.
func RunDoctor(ctx context.Context, cfg *config.Config) error {
	return RunDoctorWithOutput(ctx, cfg, os.Stdout)
}

// RunDoctorWithOutput executes diagnostics and renders results to the provided writer.
func RunDoctorWithOutput(ctx context.Context, cfg *config.Config, out io.Writer) error {
	runner := doctor.NewRunner()
	report := runner.RunAll(ctx, cfg)

	if err := doctor.PrintReport(out, report, cfg); err != nil {
		return fmt.Errorf("rendering doctor report: %w", err)
	}

	if report.Overall == doctor.StatusFail {
		return doctor.ErrChecksFailed
	}
	return nil
}
