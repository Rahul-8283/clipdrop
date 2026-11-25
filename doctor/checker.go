// Package doctor provides operational health diagnostics, environment checks,
// and automated troubleshooting capabilities for Clipdrop.
package doctor

import (
	"context"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
)

// Status represents the outcome status of a diagnostic check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// Result represents the detailed finding and remediation advice of a diagnostic check.
type Result struct {
	Name        string        `json:"name"`
	Status      Status        `json:"status"`
	Latency     time.Duration `json:"latency"`
	Summary     string        `json:"summary"`
	Remediation string        `json:"remediation,omitempty"`
}

// Check defines the interface that all diagnostic checks must satisfy.
type Check interface {
	Name() string
	Run(ctx context.Context, cfg *config.Config) *Result
}
