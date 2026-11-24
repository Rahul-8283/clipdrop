# Phase 5 — Implementation Plan: Diagnostics, Doctor & Documentation

## Overview

This document translates the Phase 5 specification ([docs/5_v1.md](file:///Users/rahulls/Projects/Screenshot_Sync/Clipdrop/docs/5_v1.md)) into a concrete step-by-step build sequence.

Phase 5 delivers operational reliability, self-service diagnostics, content retention management, an optional macOS screenshot directory watcher, and the complete technical documentation suite:
1. **Received Content Retention & Archiving** (`store/retention.go`): Automatically archives inbound items to `<configDir>/received/` with timestamp/hash naming and enforces a strict 20-item pruning ceiling.
2. **Diagnostic Engine & Checks** (`doctor/`): Implements the `Check` interface, core platform-agnostic checks, and OS-specific checks (macOS pasteboard/screencapture, Windows firewall/network profile).
3. **Formatted Terminal Diagnostics** (`doctor/printer.go` & `app/commands.go`): Powers `clipdrop doctor` with an aligned terminal status report, status badges (PASS / WARN / FAIL), actionable remediation instructions, and an overall readiness diagnosis.
4. **Optional macOS Screenshot Watcher** (`platform/screenshots/`): Watches the system screencapture directory for newly saved screenshots behind `--watch-screenshots` with 250ms debounce write-completion stabilization.
5. **Technical Documentation Suite** (`docs/`): Authors `docs/SPEC.md` (formal system specification), `docs/protocol.md` (wire protocol & schemas), and `docs/troubleshooting.md` (operational runbook).
6. **Automated Test Coverage** (`test/`): Validates retention pruning, path sanitization, diagnostic check outcomes, port collisions, corrupted credentials, and screenshot watcher logic.

---

## File Architecture for Phase 5

```
doctor/
  checker.go           — Check interface, Status enum (Pass, Warn, Fail), Result struct
  runner.go            — Sequential check execution engine, latency tracking, report aggregation
  checks_core.go       — Core checks: config dir, identity, trusted store, port, mDNS, peer pings
  checks_darwin.go     — macOS checks: pasteboard accessibility, screencapture location
  checks_windows.go    — Windows checks: Windows Defender Firewall rule, network profile (Private)
  checks_other.go      — Fallback stubs for unsupported / non-specific OS platforms
  printer.go           — Formatted terminal table printer with colored status badges & remediation
store/
  retention.go         — Inbound item archiver in received/, timestamp naming, 20-file pruning ceiling
platform/
  screenshots/
    watcher_darwin.go  — macOS screencapture directory watcher with 250ms debounce stabilization
    watcher_other.go   — Fallback stub for Windows/Linux systems
app/
  commands.go          — Implementation of RunDoctor wired to doctor.Runner
  sync.go              — Optional screenshot watcher initialization wired behind --watch-screenshots
netx/
  transport/
    server.go          — Asynchronously invoke store.ArchiveReceived on successful inbound upload
docs/
  SPEC.md              — Complete architectural reference, cryptographic invariants & non-goals
  protocol.md          — Wire protocol reference, REST endpoints, schemas, headers & status codes
  troubleshooting.md   — Operational runbook for Wi-Fi client isolation, firewall & permissions
test/
  retention_test.go    — 20-item prune ceiling, naming convention, directory traversal prevention
  doctor_test.go       — Port collision, corrupted identity, mock peer ping, table output format
  screenshots_test.go  — macOS preference reader, debouncing write stability, PNG validation
```

---

## Step-by-Step Implementation Sequence

### Step 1 — Inbound Content Archiving & Retention Policy (`store/retention.go`)
**Responsibility:**
- Define `RetentionManager` struct backed by configuration directory path.
- `EnsureDir()` creates `<configDir>/received/` with strict mode `0700`.
- `Archive(kind string, data []byte, sha256Hex string) (string, error)`:
  - Generates safe filename: `<YYYYMMDDTHHMMSSZ>_<sha256[:8]>.<png|txt>`
  - Uses `time.Now().UTC().Format("20060102T150405Z")` and validates SHA-256 length.
  - Sanitizes filenames against directory traversal (`filepath.Base`, stripping `..`, `/`, `\`).
  - Writes data atomically to `<configDir>/received/<filename>`.
  - Asynchronously triggers non-blocking `Prune()`.
- `Prune() error`:
  - Reads directory entries in `<configDir>/received/`.
  - Filters regular files, parses/records modification timestamps.
  - Sorts files chronologically (oldest first).
  - If file count exceeds 20: permanently deletes oldest files until exactly 20 remain.
- Integrate into `netx/transport/server.go`:
  - Inside `handleUpload`, after `ApplyInbound` succeeds, launch background goroutine calling `s.retention.Archive(...)`.

---

### Step 2 — Diagnostic Types & Core System Checks (`doctor/checker.go` & `doctor/checks_core.go`)
**Responsibility:**
- `checker.go`:
  - Define `Status` enum: `StatusPass`, `StatusWarn`, `StatusFail`.
  - Define `Result` struct:
    ```go
    type Result struct {
        Name        string
        Status      Status
        Latency     time.Duration
        Summary     string
        Remediation string
    }
    ```
  - Define `Check` interface:
    ```go
    type Check interface {
        Name() string
        Run(ctx context.Context, cfg *config.Config) *Result
    }
    ```
- `checks_core.go`:
  - **CheckConfigDir**: Validates `cfg.ConfigDir` exists, is writable, and permissions match `0700` (on Unix). Remediation: `"Run: chmod 700 [path] or verify disk write permissions."`
  - **CheckIdentity**: Verifies `key.pem` and `cert.pem` exist, parse as NIST P-256 ECDSA key and valid X.509 certificate, not expired. Remediation: `"Run 'clipdrop run' to regenerate a fresh device identity."`
  - **CheckTrustedStore**: Verifies `trusted_devices.json` exists or can be created, parses as valid JSON with valid schema. Remediation: `"Inspect file for JSON corruption or delete to reset pairings."`
  - **CheckPortAvailability**: Attempts temporary TCP listener on `fmt.Sprintf(":%d", cfg.Port)`. Remediation: `"Port is in use by another process. Specify an alternate with --port."`
  - **CheckMulticastDNS**: Attempts to join multicast UDP group `224.0.0.251:5353`. Remediation: `"Local network interface does not support multicast. Use --peer ip:port."`
  - **CheckPeerConnectivity**: Iterates trusted devices from store; sends `GET /v1/ping` with 3-second timeout via `transport.Client`. If all offline or unresolvable, returns `WARN` with `"Peer is offline, on a different Wi-Fi, or blocked by client isolation."`

---

### Step 3 — Platform-Specific Diagnostic Checks (`doctor/checks_darwin.go`, `doctor/checks_windows.go`, `doctor/checks_other.go`)
**Responsibility:**
- `checks_darwin.go` (build tag `//go:build darwin`):
  - **CheckPasteboardPermissions**: Tests reading from `platform/clipboard.NewReal()` pasteboard; flags `FAIL` if OS security faults or permissions are denied. Remediation: `"Ensure Terminal or iTerm2 has permissions under System Settings > Privacy & Security."`
  - **CheckScreencaptureLocation**: Runs `defaults read com.apple.screencapture location` or inspects fallback `~/Desktop`; verifies folder exists and is writable.
- `checks_windows.go` (build tag `//go:build windows`):
  - **CheckWindowsFirewall**: Inspects firewall inbound rules via `netsh advfirewall firewall show rule name="Clipdrop"` or PowerShell `Get-NetFirewallRule`. Remediation: `"Run PowerShell as Admin: New-NetFirewallRule -DisplayName 'Clipdrop' -Direction Inbound -Program '[path]' -Action Allow"`
  - **CheckWindowsNetworkProfile**: Checks active network connection profiles via PowerShell `Get-NetConnectionProfile`. Warns if any active interface is set to `Public`. Remediation: `"Current Wi-Fi is set to 'Public'. Change network profile to 'Private' in Windows Settings."`
- `checks_other.go` (build tag `//go:build !darwin && !windows`):
  - Stubs returning empty slices for OS-specific checks.

---

### Step 4 — Diagnostic Runner, Terminal Table Printer & CLI Integration (`doctor/runner.go`, `doctor/printer.go`, `app/commands.go`)
**Responsibility:**
- `doctor/runner.go`:
  - `NewRunner(customChecks ...Check) *Runner`
  - `RunAll(ctx context.Context, cfg *config.Config) *Report`
  - Assembles all core checks + OS-specific checks.
  - Measures execution latency per check with `time.Since()`.
  - Determines overall status: `Pass` (all pass), `Warn` (contains warnings, no failures), `Fail` (one or more failures).
- `doctor/printer.go`:
  - Renders formatted terminal table to `io.Writer`:
    - Header: Host OS, architecture, current user, config directory path.
    - Columns: Check Name, Status (`[ PASS ]` green, `[ WARN ]` yellow, `[ FAIL ]` red), Latency (e.g., `12ms`), Summary.
    - Remediation section: Appends actionable commands for every `WARN` or `FAIL`.
    - Overall diagnosis banner: `"Overall: SYSTEM READY FOR SYNC"` or `"Overall: ISSUES DETECTED"`.
- `app/commands.go`:
  - Update `RunDoctor(ctx context.Context, cfg *config.Config) error` to invoke `doctor.NewRunner().RunAll(ctx, cfg)` and render results using `doctor.PrintReport(os.Stdout, report)`.
  - If any check returns `StatusFail`, returns exit error or non-zero indicator.

---

### Step 5 — Optional macOS Screenshot Directory Watcher (`platform/screenshots/` & `config/`)
**Responsibility:**
- `config/config.go`:
  - Add `WatchScreenshots bool` to `Config` struct.
  - Add `--watch-screenshots` flag in `cmd/clipdrop/main.go` for `run` subcommand.
- `platform/screenshots/watcher_darwin.go` (build tag `//go:build darwin`):
  - `ResolveScreencaptureDir() (string, error)`: Evaluates `defaults read com.apple.screencapture location`; falls back to `filepath.Join(os.Getenv("HOME"), "Desktop")`.
  - `Watcher` struct: monitors target directory for newly written `.png` files.
  - Write-completion debouncing:
    - Polls newly detected files every 250 milliseconds.
    - When file size remains identical and non-zero across two successive polls, marks file write complete.
  - Reads raw PNG bytes, validates via `imaging.ValidatePNG(data)`.
  - Dispatches validated screenshot to `engine.Engine` as an outbound image event.
- `platform/screenshots/watcher_other.go` (build tag `//go:build !darwin`):
  - No-op implementation for non-macOS systems returning `nil` or unsupported log notice.
- `app/sync.go`:
  - If `cfg.WatchScreenshots` is enabled, start `screenshots.NewWatcher(...)` in a background routine bounded by root `ctx`.

---

### Step 6 — Technical Documentation Suite (`docs/SPEC.md`, `docs/protocol.md`, `docs/troubleshooting.md`)
**Responsibility:**
- `docs/SPEC.md`:
  - Architectural overview: local network boundaries, zeroconf discovery, mTLS 1.3 certificate pinning, PAKE authentication.
  - Security invariants: zero pre-shared keys, ephemeral pairing port, 3-attempt brute-force lockout, single-use token lifecycle.
  - Concurrency model: 5 core background goroutines, root context cancellation, 3-second teardown budget.
  - Non-goals: no cloud relays, no long-term infinite clipboard index, no privilege escalation.
- `docs/protocol.md`:
  - Formal REST wire protocol:
    - `GET /v1/ping`: Protocol verification, timestamp exchange.
    - `POST /v1/offer`: Pre-flight transfer negotiation (`OfferRequest` / `OfferResponse`).
    - `PUT /v1/items/{id}`: Binary streaming upload with `X-Sha256`, `X-Protocol-Version`.
    - Pairing ceremony endpoints on ephemeral listener.
  - Exact JSON request and response schemas, custom HTTP headers, status code mappings (`200`, `400`, `409`, `413`, `422`).
- `docs/troubleshooting.md`:
  - Practical operational runbook:
    - Wi-Fi access point client isolation (preventing peer-to-peer multicast).
    - Windows Defender Firewall profile remediation (switching Public to Private, adding rule).
    - macOS pasteboard and terminal accessibility permissions.
    - Command-line diagnostic validation using `ping`, `dns-sd`, and `clipdrop doctor`.

---

### Step 7 — Automated Test Suites in `test/`
**Test Suites:**
1. `test/retention_test.go`:
   - Enforce 20-file limit: ingest 25 items, verify exactly 20 newest remain and 5 oldest are pruned.
   - Naming convention: verify files match `<timestamp>_<hash8>.<ext>` regex.
   - Path traversal prevention: verify filenames containing `../` or invalid separators are sanitized.
2. `test/doctor_test.go`:
   - Port collision test: bind port 47820, verify port check returns `FAIL` with `--port` remediation.
   - Corrupted identity test: truncate `cert.pem`, verify identity check returns `FAIL`.
   - Report printer test: render mock report and assert presence of status badges, columns, and banner.
3. `test/screenshots_test.go`:
   - Preference reader test: test default fallback to Desktop when preference is unset.
   - Debounce write stabilization test: simulate growing file and verify event fires only after size stabilizes.

---

## Acceptance Criteria Checklist

- [ ] Retention manager archives received items to `<configDir>/received/` with permissions `0700`.
- [ ] Retention manager strictly enforces 20-item ceiling, unlinking oldest files asynchronously.
- [ ] File naming matches `<YYYYMMDDTHHMMSSZ>_<sha256[:8]>.<png|txt>` with strict path sanitization.
- [ ] `clipdrop doctor` executes all platform-agnostic checks (config dir, identity, store, port, mDNS, peer ping).
- [ ] `clipdrop doctor` executes OS-specific checks (macOS pasteboard/screencapture, Windows firewall/profile).
- [ ] `clipdrop doctor` renders an aligned, colored terminal table with actionable remediation instructions.
- [ ] Optional macOS screenshot watcher activates via `--watch-screenshots` and debounces writes over 250ms intervals.
- [ ] Complete technical documentation suite authored: `docs/SPEC.md`, `docs/protocol.md`, `docs/troubleshooting.md`.
- [ ] All new and existing unit, integration, and diagnostic tests pass with `go test -race -v ./test/...`.
- [ ] Binary compiles cleanly with `make build`.
