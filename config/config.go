// Package config provides runtime configuration, OS-compliant config
// directory management, and permission enforcement for Clipdrop.
package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Config holds all runtime settings for a Clipdrop instance.
// It is populated once at startup from CLI flags and defaults,
// then passed read-only to every component.
type Config struct {
	// Network
	Port     int    // mTLS listener port (default 47820)
	PeerAddr string // manual --peer ip:port override

	// Behaviour flags
	ImagesOnly bool // --images-only: suppress text sync
	NoText     bool // --no-text: alias for ImagesOnly
	Verbose    bool // --verbose: elevate log level to DEBUG

	// Identity
	DeviceName string // local hostname, shown to peers

	// Resolved paths
	ConfigDir string // absolute path to the application config directory

	// Payload size limits
	MaxImageBytes int64 // maximum accepted image payload (bytes)
	MaxTextBytes  int64 // maximum accepted text payload (bytes)

	// Operational timeouts and intervals
	HeartbeatInterval time.Duration // how often to ping trusted peers
	ConnectTimeout    time.Duration // TCP dial timeout
	OfferTimeout      time.Duration // POST /v1/offer round-trip budget
	UploadTimeout     time.Duration // PUT  /v1/items/{id} upload budget
}

// Defaults returns a Config populated with safe production defaults.
// DeviceName is resolved from the OS hostname; it falls back to "unknown"
// if the system call fails.
func Defaults() Config {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return Config{
		Port:              47820,
		DeviceName:        hostname,
		MaxImageBytes:     26_214_400, // 25 MB
		MaxTextBytes:      1_048_576,  // 1 MB
		HeartbeatInterval: 5 * time.Second,
		ConnectTimeout:    3 * time.Second,
		OfferTimeout:      3 * time.Second,
		UploadTimeout:     15 * time.Second,
	}
}

// Dir returns the platform-correct Clipdrop configuration directory path.
// If the CLIPDROP_CONFIG_DIR environment variable is set, it takes precedence.
// Otherwise, it delegates to os.UserConfigDir() so the default result is:
//
//	macOS   → ~/Library/Application Support/clipdrop
//	Windows → %AppData%\Roaming\clipdrop
//	Linux   → ~/.config/clipdrop
//
// Dir does not create or validate the directory — call EnsureDir for that.
func Dir() (string, error) {
	if custom := os.Getenv("CLIPDROP_CONFIG_DIR"); custom != "" {
		return custom, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "clipdrop"), nil
}

// EnsureDir creates dir with mode 0700 if it does not already exist.
// If the directory is already present, the call is a no-op.
// It does not modify permissions of an existing directory; use CheckPerms
// to audit an existing directory.
func EnsureDir(dir string) error {
	return os.MkdirAll(dir, 0700)
}

// CheckPerms inspects dir and emits a slog.Warn when the Unix permission
// bits are wider than 0700 (i.e., any group or world read/write/execute
// bit is set). On Windows the function returns immediately without
// checking because Windows uses ACLs rather than Unix mode bits.
func CheckPerms(dir string) {
	if runtime.GOOS == "windows" {
		return
	}

	info, err := os.Stat(dir)
	if err != nil {
		slog.Warn("config: cannot stat config directory",
			"dir", dir,
			"err", err,
		)
		return
	}

	// Isolate group and world permission bits (octal 0077).
	// If any of these bits are set the directory is accessible
	// to users other than the owner, which is too permissive for
	// a directory that may contain private keys and trust records.
	if info.Mode().Perm()&0077 != 0 {
		slog.Warn("config: directory permissions are too wide",
			"dir", dir,
			"perm", info.Mode().Perm(),
			"hint", "run: chmod 700 "+dir,
		)
	}
}
