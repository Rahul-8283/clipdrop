//go:build darwin

package doctor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
)

// PlatformChecks returns all macOS-specific diagnostic checks.
func PlatformChecks() []Check {
	return []Check{
		&PasteboardPermissionsCheck{},
		&ScreencaptureLocationCheck{},
	}
}

// PasteboardPermissionsCheck tests whether the current process can access the macOS pasteboard.
type PasteboardPermissionsCheck struct{}

func (c *PasteboardPermissionsCheck) Name() string {
	return "macOS Pasteboard Permissions"
}

func (c *PasteboardPermissionsCheck) Run(_ context.Context, _ *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	clip, err := clipboard.NewReal()
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Failed to initialize system pasteboard: %v", err)
		res.Remediation = "Ensure Terminal or iTerm2 has permissions under System Settings > Privacy & Security."
		return res
	}

	_, rErr := clip.Read()
	if rErr != nil && !errors.Is(rErr, clipboard.ErrEmpty) {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Cannot read system pasteboard: %v", rErr)
		res.Remediation = "Ensure Terminal or iTerm2 has permissions under System Settings > Privacy & Security."
		return res
	}

	res.Status = StatusPass
	res.Summary = "Pasteboard initialized and accessible without OS security faults"
	return res
}

// ScreencaptureLocationCheck verifies the configured destination directory for macOS screenshots.
type ScreencaptureLocationCheck struct{}

func (c *ScreencaptureLocationCheck) Name() string {
	return "macOS Screencapture Location"
}

func (c *ScreencaptureLocationCheck) Run(ctx context.Context, _ *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	targetDir := ""

	// Evaluate: defaults read com.apple.screencapture location
	out, err := exec.CommandContext(ctx, "defaults", "read", "com.apple.screencapture", "location").Output()
	if err == nil {
		targetDir = strings.TrimSpace(string(out))
	}

	// Fallback to ~/Desktop if preference is not explicitly configured
	if targetDir == "" {
		homeDir, hErr := os.UserHomeDir()
		if hErr == nil {
			targetDir = filepath.Join(homeDir, "Desktop")
		}
	}

	if targetDir == "" {
		res.Status = StatusWarn
		res.Summary = "Cannot determine screencapture directory (defaults read returned empty, home dir unavailable)"
		res.Remediation = "Run: defaults write com.apple.screencapture location ~/Desktop"
		return res
	}

	// Expand leading tilde if present
	if strings.HasPrefix(targetDir, "~/") {
		homeDir, _ := os.UserHomeDir()
		targetDir = filepath.Join(homeDir, targetDir[2:])
	}

	info, err := os.Stat(targetDir)
	if err != nil {
		res.Status = StatusWarn
		res.Summary = fmt.Sprintf("Configured screenshot directory %s does not exist: %v", targetDir, err)
		res.Remediation = fmt.Sprintf("Run: mkdir -p %s or reset with: defaults delete com.apple.screencapture location", targetDir)
		return res
	}

	if !info.IsDir() {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Screenshot destination %s exists but is not a directory", targetDir)
		res.Remediation = "Reset screenshot directory with: defaults delete com.apple.screencapture location"
		return res
	}

	// Test disk writability
	tmpFile, err := os.CreateTemp(targetDir, ".screencapture-test-*")
	if err != nil {
		res.Status = StatusWarn
		res.Summary = fmt.Sprintf("Screenshot directory %s is not writable: %v", targetDir, err)
		res.Remediation = fmt.Sprintf("Check permissions on %s or grant Full Disk Access to Terminal.", targetDir)
		return res
	}
	tmpName := tmpFile.Name()
	_ = tmpFile.Close()
	_ = os.Remove(tmpName)

	res.Status = StatusPass
	res.Summary = fmt.Sprintf("Screenshots saved to %s (directory exists and is writable)", targetDir)
	return res
}
