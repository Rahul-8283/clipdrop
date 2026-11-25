//go:build windows

package doctor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
)

// PlatformChecks returns all Windows-specific diagnostic checks.
func PlatformChecks() []Check {
	return []Check{
		&WindowsFirewallCheck{},
		&WindowsNetworkProfileCheck{},
	}
}

// WindowsFirewallCheck verifies whether Windows Defender Firewall has an inbound rule for Clipdrop.
type WindowsFirewallCheck struct{}

func (c *WindowsFirewallCheck) Name() string {
	return "Windows Firewall"
}

func (c *WindowsFirewallCheck) Run(ctx context.Context, _ *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	// Execute: netsh advfirewall firewall show rule name=Clipdrop
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=Clipdrop")
	out, err := cmd.CombinedOutput()
	outputStr := string(out)

	if err != nil || !strings.Contains(outputStr, "Enabled:") || strings.Contains(outputStr, "No rules match") {
		res.Status = StatusWarn
		res.Summary = "No active inbound firewall rule found for 'Clipdrop'"
		res.Remediation = "Run PowerShell as Admin: New-NetFirewallRule -DisplayName 'Clipdrop' -Direction Inbound -Program (Get-Process -Id $PID).Path -Action Allow"
		return res
	}

	if strings.Contains(outputStr, "Enabled:                              No") {
		res.Status = StatusWarn
		res.Summary = "Inbound firewall rule for 'Clipdrop' exists but is disabled"
		res.Remediation = "Run PowerShell as Admin: Set-NetFirewallRule -DisplayName 'Clipdrop' -Enabled True"
		return res
	}

	res.Status = StatusPass
	res.Summary = "Inbound firewall rule for Clipdrop is configured and active"
	return res
}

// WindowsNetworkProfileCheck inspects whether active network connections are classified as Private.
type WindowsNetworkProfileCheck struct{}

func (c *WindowsNetworkProfileCheck) Name() string {
	return "Windows Network Profile"
}

func (c *WindowsNetworkProfileCheck) Run(ctx context.Context, _ *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory")
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.Status = StatusWarn
		res.Summary = fmt.Sprintf("Failed to query network profile: %v", err)
		res.Remediation = "Ensure PowerShell is available and network adapters are active."
		return res
	}

	category := strings.TrimSpace(string(out))
	if strings.Contains(category, "Public") {
		res.Status = StatusWarn
		res.Summary = "Active network connection is classified as 'Public'"
		res.Remediation = "Current Wi-Fi is set to 'Public'. Change network profile to 'Private' in Windows Settings."
		return res
	}

	res.Status = StatusPass
	res.Summary = fmt.Sprintf("Active network profile is '%s'", category)
	return res
}
