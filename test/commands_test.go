package test

import (
	"context"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/Rahul-8283/clipdrop/app"
	"github.com/Rahul-8283/clipdrop/config"
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

// --- Stub handlers all return nil ---

func TestStubs_AllReturnNil(t *testing.T) {
	cfg := config.Defaults()
	ctx := context.Background()

	stubs := []struct {
		name string
		fn   func(context.Context, *config.Config) error
	}{
		{"RunSync", app.RunSync},
		{"RunPairHost", app.RunPairHost},
		{"RunPairJoin", app.RunPairJoin},
		{"RunDevices", app.RunDevices},
		{"RunUnpair", app.RunUnpair},
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

// TestStubs_ResepctCancelledContext verifies that all stubs return when
// their context is already cancelled — they must not block.
func TestStubs_RespectCancelledContext(t *testing.T) {
	cfg := config.Defaults()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stubs := []struct {
		name string
		fn   func(context.Context, *config.Config) error
	}{
		{"RunSync", app.RunSync},
		{"RunPairHost", app.RunPairHost},
		{"RunPairJoin", app.RunPairJoin},
		{"RunDevices", app.RunDevices},
		{"RunUnpair", app.RunUnpair},
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
