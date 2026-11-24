package doctor

import (
	"context"
	"errors"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
)

// ErrChecksFailed is returned when one or more diagnostic checks fail.
var ErrChecksFailed = errors.New("doctor: one or more diagnostic checks failed")

// Report holds the aggregated findings, overall status, and total runtime of all diagnostic checks.
type Report struct {
	Results      []*Result     `json:"results"`
	Overall      Status        `json:"overall"`
	TotalLatency time.Duration `json:"total_latency"`
}

// Runner coordinates the sequential execution of diagnostic checks.
type Runner struct {
	checks []Check
}

// NewRunner constructs a Runner. If customChecks are provided, they are used;
// otherwise it defaults to AllChecks() (standard core checks + platform checks).
func NewRunner(customChecks ...Check) *Runner {
	if len(customChecks) > 0 {
		return &Runner{checks: customChecks}
	}
	return &Runner{checks: AllChecks()}
}

// Checks returns the list of diagnostic checks registered on this runner.
func (r *Runner) Checks() []Check {
	return r.checks
}

// RunAll executes all registered checks sequentially, tracks elapsed time,
// and determines the overall system diagnostic status.
func (r *Runner) RunAll(ctx context.Context, cfg *config.Config) *Report {
	start := time.Now()
	report := &Report{
		Results: make([]*Result, 0, len(r.checks)),
		Overall: StatusPass,
	}

	for _, ch := range r.checks {
		if ctx.Err() != nil {
			report.Results = append(report.Results, &Result{
				Name:        ch.Name(),
				Status:      StatusFail,
				Summary:     "Check cancelled by context",
				Remediation: "Rerun diagnostic check with a valid context.",
			})
			report.Overall = StatusFail
			break
		}

		res := ch.Run(ctx, cfg)
		if res == nil {
			continue
		}
		report.Results = append(report.Results, res)

		if res.Status == StatusFail {
			report.Overall = StatusFail
		} else if res.Status == StatusWarn && report.Overall != StatusFail {
			report.Overall = StatusWarn
		}
	}

	report.TotalLatency = time.Since(start)
	return report
}
