package doctor

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
)

// ANSI color escape sequences for terminal output.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
)

// PrintReport writes a formatted, aligned terminal diagnostic report to w.
func PrintReport(w io.Writer, rep *Report, cfg *config.Config) error {
	if rep == nil {
		return nil
	}

	// 1. Header Information
	currUser := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		currUser = u.Username
	} else if envUser := os.Getenv("USER"); envUser != "" {
		currUser = envUser
	}

	configDir := ""
	if cfg != nil && cfg.ConfigDir != "" {
		configDir = cfg.ConfigDir
	} else {
		configDir, _ = config.Dir()
	}

	fmt.Fprintf(w, "%s=== Clipdrop Diagnostics (doctor) ===%s\n", ansiBold, ansiReset)
	fmt.Fprintf(w, "Host OS:         %s (%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "Current User:    %s\n", currUser)
	fmt.Fprintf(w, "Config Dir:      %s\n", configDir)
	fmt.Fprintf(w, "Total Latency:   %s\n\n", formatLatency(rep.TotalLatency))

	// 2. Table Headers
	fmt.Fprintf(w, "%-30s %-10s %-8s %s\n", "CHECK", "STATUS", "LATENCY", "SUMMARY")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 80))

	// 3. Check Rows
	for _, res := range rep.Results {
		statusBadge := formatBadge(res.Status)
		latStr := formatLatency(res.Latency)
		fmt.Fprintf(w, "%-30s %s   %-6s  %s\n", res.Name, statusBadge, latStr, res.Summary)
	}
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("-", 80))

	// 4. Remediation Advice Section
	var issues []*Result
	for _, res := range rep.Results {
		if (res.Status == StatusWarn || res.Status == StatusFail) && res.Remediation != "" {
			issues = append(issues, res)
		}
	}

	if len(issues) > 0 {
		fmt.Fprintf(w, "%sRemediation Advice:%s\n", ansiBold, ansiReset)
		for _, iss := range issues {
			tag := ansiYellow + "[WARN]" + ansiReset
			if iss.Status == StatusFail {
				tag = ansiRed + "[FAIL]" + ansiReset
			}
			fmt.Fprintf(w, "  • %s %s%s%s:\n      %s\n", tag, ansiBold, iss.Name, ansiReset, iss.Remediation)
		}
		fmt.Fprintln(w)
	}

	// 5. Overall Diagnosis Banner
	switch rep.Overall {
	case StatusPass:
		fmt.Fprintf(w, "%s%sOverall: SYSTEM READY FOR SYNC%s\n", ansiBold, ansiGreen, ansiReset)
	case StatusWarn:
		fmt.Fprintf(w, "%s%sOverall: SYSTEM FUNCTIONAL WITH WARNINGS%s\n", ansiBold, ansiYellow, ansiReset)
	case StatusFail:
		fmt.Fprintf(w, "%s%sOverall: ISSUES DETECTED%s\n", ansiBold, ansiRed, ansiReset)
	}

	return nil
}

func formatBadge(s Status) string {
	switch s {
	case StatusPass:
		return fmt.Sprintf("%s[ PASS ]%s", ansiGreen, ansiReset)
	case StatusWarn:
		return fmt.Sprintf("%s[ WARN ]%s", ansiYellow, ansiReset)
	case StatusFail:
		return fmt.Sprintf("%s[ FAIL ]%s", ansiRed, ansiReset)
	default:
		return fmt.Sprintf("[ %-4s ]", string(s))
	}
}

func formatLatency(d time.Duration) string {
	if d < time.Millisecond {
		return "<1ms"
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
