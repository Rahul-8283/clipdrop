package test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/app"
	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

// captureStdout redirects os.Stdout to an in-memory pipe for the duration
// of fn, then restores it and returns everything that was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error: %v", err)
	}
	original := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = original

	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy() error: %v", err)
	}
	return buf.String()
}

// --- PrintVersion ---

func TestPrintVersion_ContainsClipdropVersion(t *testing.T) {
	out := captureStdout(t, app.PrintVersion)
	if !strings.Contains(out, "clipdrop version") {
		t.Errorf("PrintVersion() output missing 'clipdrop version'; got:\n%s", out)
	}
}

func TestPrintVersion_ContainsProtocolVersion(t *testing.T) {
	out := captureStdout(t, app.PrintVersion)
	if !strings.Contains(out, "protocol version 1") {
		t.Errorf("PrintVersion() output missing 'protocol version 1'; got:\n%s", out)
	}
}

func TestPrintVersion_ContainsGoVersion(t *testing.T) {
	out := captureStdout(t, app.PrintVersion)
	if !strings.Contains(out, runtime.Version()) {
		t.Errorf("PrintVersion() output missing Go version %q; got:\n%s", runtime.Version(), out)
	}
}

func TestPrintVersion_ExactLineCount(t *testing.T) {
	out := captureStdout(t, app.PrintVersion)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Errorf("PrintVersion() produced %d line(s); want 3:\n%s", len(lines), out)
	}
}

// --- Remaining stub handlers return nil ---

func TestStubs_AllReturnNil(t *testing.T) {
	cfg := config.Defaults()
	ctx := context.Background()

	stubs := []struct {
		name string
		fn   func(context.Context, *config.Config) error
	}{
		{"RunPairHost", app.RunPairHost},
		{"RunPairJoin", app.RunPairJoin},
		{"RunDoctor", app.RunDoctor},
	}

	for _, tc := range stubs {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(ctx, &cfg); err != nil {
				t.Errorf("%s() returned unexpected error: %v", tc.name, err)
			}
		})
	}
}

func TestRunSync_CancelledContext(t *testing.T) {
	cfg := config.Defaults()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := app.RunSync(ctx, &cfg)
	if err != nil && !errors.Is(err, clipboard.ErrUnavailable) {
		t.Fatalf("RunSync failed on cancelled context: %v", err)
	}
}

// TestStubs_RespectCancelledContext verifies that all stubs return when
// their context is already cancelled — they must not block.
func TestStubs_RespectCancelledContext(t *testing.T) {
	cfg := config.Defaults()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stubs := []struct {
		name string
		fn   func(context.Context, *config.Config) error
	}{
		{"RunPairHost", app.RunPairHost},
		{"RunPairJoin", app.RunPairJoin},
		{"RunDoctor", app.RunDoctor},
	}

	for _, tc := range stubs {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn(ctx, &cfg)
			if err != nil {
				t.Errorf("%s() returned error on cancelled context: %v", tc.name, err)
			}
		})
	}
}

// --- RunDevices & RunUnpair Tests ---

func TestRunDevices_EmptyStore(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tmpDir

	var out bytes.Buffer
	err := app.RunDevicesTo(context.Background(), &cfg, &out)
	if err != nil {
		t.Fatalf("RunDevicesTo failed: %v", err)
	}

	expected := "No paired devices. Run 'clipdrop pair' to link a peer.\n"
	if out.String() != expected {
		t.Errorf("output mismatch:\ngot:  %q\nwant: %q", out.String(), expected)
	}
}

func TestRunDevices_PopulatedTable(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tmpDir

	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	dev1 := &store.Device{
		ID:          "a1b2c3d4e5f67890abcdef1234567890",
		Name:        "macbook-pro",
		OS:          "darwin",
		PairedAt:    time.Now().Add(-2 * time.Minute),
		LastSeen:    time.Now().Add(-30 * time.Second),
		LastAddress: "192.168.1.10:47820",
	}
	dev2 := &store.Device{
		ID:          "f9e8d7c6b5a432100987654321fedcba",
		Name:        "windows-pc",
		OS:          "windows",
		PairedAt:    time.Now().Add(-24 * time.Hour),
		LastSeen:    time.Now().Add(-5 * time.Minute),
		LastAddress: "",
	}
	_ = st.Add(dev1)
	_ = st.Add(dev2)

	// Non-verbose: IDs truncated to 16 chars
	var out bytes.Buffer
	cfg.Verbose = false
	if err := app.RunDevicesTo(context.Background(), &cfg, &out); err != nil {
		t.Fatalf("RunDevicesTo failed: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "NAME") || !strings.Contains(output, "DEVICE ID") || !strings.Contains(output, "LAST ADDRESS") {
		t.Fatalf("table missing headers:\n%s", output)
	}
	if !strings.Contains(output, "macbook-pro") || !strings.Contains(output, "a1b2c3d4e5f67890") {
		t.Fatalf("table missing macbook entry or truncated ID:\n%s", output)
	}
	if strings.Contains(output, "a1b2c3d4e5f67890abcdef") {
		t.Fatalf("non-verbose output should not contain full 32-char ID:\n%s", output)
	}
	if !strings.Contains(output, "windows-pc") || !strings.Contains(output, "f9e8d7c6b5a43210") {
		t.Fatalf("table missing windows-pc entry:\n%s", output)
	}
	if !strings.Contains(output, "192.168.1.10:47820") {
		t.Fatalf("table missing address:\n%s", output)
	}

	// Verbose: Full ID present
	var outVerbose bytes.Buffer
	cfg.Verbose = true
	if err := app.RunDevicesTo(context.Background(), &cfg, &outVerbose); err != nil {
		t.Fatalf("RunDevicesTo verbose failed: %v", err)
	}
	verboseOutput := outVerbose.String()
	if !strings.Contains(verboseOutput, "a1b2c3d4e5f67890abcdef1234567890") {
		t.Fatalf("verbose output missing full device ID:\n%s", verboseOutput)
	}
}

func TestRunUnpair_SuccessByNameAndID(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tmpDir

	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	dev := &store.Device{
		ID:       "a1b2c3d4e5f67890abcdef1234567890",
		Name:     "laptop-work",
		OS:       "darwin",
		PairedAt: time.Now(),
		LastSeen: time.Now(),
	}
	_ = st.Add(dev)

	// Unpair by exact name
	var out bytes.Buffer
	var errOut bytes.Buffer
	err = app.RunUnpairTargetTo(context.Background(), &cfg, "laptop-work", &out, &errOut)
	if err != nil {
		t.Fatalf("RunUnpairTargetTo by name failed: %v", err)
	}

	expectedOut := "Revoked trust for laptop-work (a1b2c3d4e5f67890).\n"
	if out.String() != expectedOut {
		t.Errorf("unpair output mismatch: got %q, want %q", out.String(), expectedOut)
	}

	// Re-add and unpair by ID prefix
	_ = st.Add(dev)
	out.Reset()
	errOut.Reset()
	err = app.RunUnpairTargetTo(context.Background(), &cfg, "a1b2c3d4e5f67890", &out, &errOut)
	if err != nil {
		t.Fatalf("RunUnpairTargetTo by ID failed: %v", err)
	}
	if out.String() != expectedOut {
		t.Errorf("unpair by ID output mismatch: got %q, want %q", out.String(), expectedOut)
	}

	// Verify device removed
	stReloaded, _ := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if stReloaded.IsTrusted(dev.ID) {
		t.Errorf("device should have been removed from store")
	}
}

func TestRunUnpair_NotFound_Remediation(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tmpDir

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := app.RunUnpairTargetTo(context.Background(), &cfg, "nonexistent-device", &out, &errOut)
	if err == nil {
		t.Fatal("expected error for nonexistent device, got nil")
	}

	expectedErr := "error: device 'nonexistent-device' not found. Run 'clipdrop devices' to list paired devices.\n"
	if errOut.String() != expectedErr {
		t.Errorf("remediation message mismatch:\ngot:  %q\nwant: %q", errOut.String(), expectedErr)
	}
}

func TestRunUnpair_EmptyTarget(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tmpDir

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := app.RunUnpairTargetTo(context.Background(), &cfg, "   ", &out, &errOut)
	if err == nil {
		t.Fatal("expected error for empty target, got nil")
	}
}

func TestRunUnpair_FromOSArgs(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tmpDir

	st, _ := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	_ = st.Add(&store.Device{
		ID:   "abcdef12345678901234567890123456",
		Name: "test-device",
		OS:   "linux",
	})

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"clipdrop", "unpair", "test-device"}
	if err := app.RunUnpair(context.Background(), &cfg); err != nil {
		t.Fatalf("RunUnpair with os.Args failed: %v", err)
	}
}
