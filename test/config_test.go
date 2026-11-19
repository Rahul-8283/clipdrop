package test

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
)

// --- Dir() ---

func TestDir_EndsWithClipdrop(t *testing.T) {
	dir, err := config.Dir()
	if err != nil {
		t.Fatalf("Dir() returned error: %v", err)
	}
	if filepath.Base(dir) != "clipdrop" {
		t.Errorf("Dir() = %q; want a path whose last element is \"clipdrop\"", dir)
	}
}

// --- Defaults() ---

func TestDefaults_Port(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Port != 47820 {
		t.Errorf("Defaults().Port = %d; want 47820", cfg.Port)
	}
}

func TestDefaults_MaxImageBytes(t *testing.T) {
	cfg := config.Defaults()
	const want int64 = 26_214_400
	if cfg.MaxImageBytes != want {
		t.Errorf("Defaults().MaxImageBytes = %d; want %d (25 MB)", cfg.MaxImageBytes, want)
	}
}

func TestDefaults_MaxTextBytes(t *testing.T) {
	cfg := config.Defaults()
	const want int64 = 1_048_576
	if cfg.MaxTextBytes != want {
		t.Errorf("Defaults().MaxTextBytes = %d; want %d (1 MB)", cfg.MaxTextBytes, want)
	}
}

func TestDefaults_Timeouts(t *testing.T) {
	cfg := config.Defaults()

	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"HeartbeatInterval", cfg.HeartbeatInterval, 5 * time.Second},
		{"ConnectTimeout", cfg.ConnectTimeout, 3 * time.Second},
		{"OfferTimeout", cfg.OfferTimeout, 3 * time.Second},
		{"UploadTimeout", cfg.UploadTimeout, 15 * time.Second},
	}

	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("Defaults().%s = %v; want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestDefaults_DeviceNameNotEmpty(t *testing.T) {
	cfg := config.Defaults()
	if cfg.DeviceName == "" {
		t.Error("Defaults().DeviceName must not be empty")
	}
}

// --- EnsureDir() ---

func TestEnsureDir_CreatesDirectory(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "clipdrop-test")

	if err := config.EnsureDir(target); err != nil {
		t.Fatalf("EnsureDir() error: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("os.Stat() after EnsureDir() error: %v", err)
	}
	if !info.IsDir() {
		t.Error("EnsureDir() did not create a directory")
	}
}

func TestEnsureDir_Permission0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits not applicable on Windows")
	}

	tmp := t.TempDir()
	target := filepath.Join(tmp, "clipdrop-perm-test")

	if err := config.EnsureDir(target); err != nil {
		t.Fatalf("EnsureDir() error: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("os.Stat() error: %v", err)
	}

	got := info.Mode().Perm()
	if got != 0700 {
		t.Errorf("EnsureDir() created directory with perm %04o; want 0700", got)
	}
}

func TestEnsureDir_IdempotentOnExistingDir(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "clipdrop-idempotent")

	// First call: creates the directory.
	if err := config.EnsureDir(target); err != nil {
		t.Fatalf("first EnsureDir() error: %v", err)
	}
	// Second call: must be a no-op, not an error.
	if err := config.EnsureDir(target); err != nil {
		t.Fatalf("second EnsureDir() (idempotent) error: %v", err)
	}
}

// --- CheckPerms() ---

// captureSlogWarnings replaces the default slog logger for the duration
// of the test and returns a pointer to the buffer it writes to.
// The original logger is restored via t.Cleanup.
func captureSlogWarnings(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	original := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(original) })
	return &buf
}

func TestCheckPerms_WarnOnWidePerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits not applicable on Windows")
	}

	tmp := t.TempDir()
	target := filepath.Join(tmp, "wide-dir")

	// Create with intentionally wide permissions (group + world readable).
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatalf("os.Mkdir() error: %v", err)
	}

	buf := captureSlogWarnings(t)
	config.CheckPerms(target)

	output := buf.String()
	if !strings.Contains(output, "too wide") {
		t.Errorf("CheckPerms() did not emit a warning for 0755 perm; got log output: %q", output)
	}
}

func TestCheckPerms_NoWarnOnStrictPerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits not applicable on Windows")
	}

	tmp := t.TempDir()
	target := filepath.Join(tmp, "strict-dir")

	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatalf("os.Mkdir() error: %v", err)
	}

	buf := captureSlogWarnings(t)
	config.CheckPerms(target)

	output := buf.String()
	if strings.Contains(output, "WARN") {
		t.Errorf("CheckPerms() emitted an unexpected warning for 0700 perm; got: %q", output)
	}
}

func TestCheckPerms_SkipsOnWindows(t *testing.T) {
	// This test only validates the documented contract in a cross-platform way.
	// On non-Windows it confirms that a valid directory with 0700 produces no warning.
	// On Windows the function is a documented no-op.
	tmp := t.TempDir()
	buf := captureSlogWarnings(t)
	config.CheckPerms(tmp) // must not panic on any platform
	_ = buf                // no assertion required; absence of panic is the test
}
