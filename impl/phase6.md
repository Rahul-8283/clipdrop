# Phase 6 — Implementation Plan: End-to-End Testing, Security Audit & Release Verification

## Overview

This document translates the Phase 6 specification ([docs/6_v1.md](file:///Users/rahulls/Projects/Screenshot_Sync/Clipdrop/docs/6_v1.md)) into a concrete step-by-step verification and hardening sequence.

Phase 6 is the final release gate for Clipdrop v1. It certifies concurrency safety, adversarial security boundaries, fault resilience, performance targets, and physical cross-platform (macOS ↔ Windows) operation:
1. **Concurrency & Goroutine Leak Audit** (`test/concurrency_test.go`): Stress-tests simultaneous inbound/outbound sync, routing table mutations during pings, mid-transfer cancellations, and goroutine baseline recovery after 100 transfers.
2. **Adversarial & Security Boundary Suite** (`test/security_test.go`): Certifies zero-trust TLS rejection of unpaired nodes, payload hash tampering defense (HTTP 422), spoofed PNG rejection (HTTP 400), oversized stream truncation (HTTP 413), and PAKE brute-force/expiration lockouts.
3. **Fault Injection & Resilience Suite** (`test/resilience_test.go`): Validates peer IP roaming, mid-transfer abrupt EOF recovery without clipboard pollution, rapid consecutive copy stabilization, and `--images-only` policy enforcement.
4. **Performance & Memory Benchmarks** (`test/benchmark_test.go`): Measures 50KB text sync latency (< 500ms), 5MB image sync latency (< 2.0s), and heap memory stability across 50 consecutive transfers.
5. **Cross-Platform Build & README Audit** (`Makefile`, `README.md`): Verifies clean cross-compilation for macOS and Windows and ensures `README.md` setup instructions remain under 10 clear steps.
6. **Physical Hardware Sign-Off Execution** (macOS ↔ Windows): Executes the real-OS-clipboard test matrix (TC-01 to TC-08), 10-minute echo audit, Wi-Fi/sleep-wake recovery, and `clipdrop doctor` verification.

---

## File Architecture for Phase 6

```
test/
  concurrency_test.go  — Race stress tests, goroutine leak baseline/teardown audit, concurrent copy/upload
  security_test.go     — Unpaired intruder mTLS drop, byte tampering, spoofed PNG, 26MB stream, PAKE attacks
  resilience_test.go   — IP roaming recovery, mid-transfer EOF drop, rapid triple copy, --images-only policy
  benchmark_test.go    — Latency benchmarks (50KB text, 5MB PNG) and 50-transfer heap stability check
README.md              — Final verification of <10-step macOS/Windows installation & quickstart guide
impl/
  phase6.md            — Phase 6 execution plan and final release sign-off checklist
```

---

## Step-by-Step Implementation Sequence

### Step 1 — Concurrency, Race Detection & Goroutine Leak Audit (`test/concurrency_test.go`)
**Responsibility:**
- **Goroutine Baseline & Leak Audit**:
  - Record `runtime.NumGoroutine()` baseline before starting `SyncPipeline`.
  - Start pipeline, execute 100 sequential offer + upload cycles, allow idle drain, cancel root context, and assert goroutine count returns to baseline within 3 seconds (zero leaked routines).
- **Simultaneous Inbound + Outbound Race**:
  - Trigger a local clipboard write on Node A at the exact moment Node B streams an inbound payload to Node A. Run under `-race` with zero data races.
- **Routing Table Concurrent Mutation**:
  - Run `PresenceMonitor` heartbeat ticks while concurrently mutating `discovery.Resolver` via `UpdateFromMDNS` and `RemoveMDNS` across multiple goroutines.
- **Mid-Transfer Cancellation**:
  - Cancel root `ctx` while a multi-megabyte `PUT /v1/items/{id}` stream is active; verify server and client exit cleanly within the 3-second shutdown budget.

---

### Step 2 — Adversarial & Security Boundary Tests (`test/security_test.go`)
**Responsibility:**
- **Intruder Rejection Test**:
  - Spin up paired Node A and Node B, plus an untrusted rogue Node C with its own valid P-256 identity.
  - Direct Node C to issue `GET /v1/ping`, `POST /v1/offer`, and `PUT /v1/items/{id}` against Node A.
  - Assert TLS 1.3 handshake fails inside `verifyPeerCertificate` (`ErrUntrustedPeer`) and Node A's clipboard remains untouched.
- **Payload Tampering & Validation Defense**:
  - Alter 1 byte of payload after computing `X-Sha256` -> assert server returns `HTTP 422 Unprocessable Entity` and does not write to clipboard.
  - Send valid 8-byte PNG magic header with corrupted `IHDR` chunk -> assert server returns `HTTP 400 Bad Request`.
  - Stream 26MB payload (>25MB `MaxImageBytes` ceiling) -> assert server truncates/rejects with `HTTP 413 Request Entity Too Large`.
- **Pairing Attack Resistance**:
  - Verify 3 consecutive wrong PAKE attempts immediately close the ephemeral pairing host listener.
  - Verify expired pairing session rejects late joiners cleanly.

---

### Step 3 — Fault Injection & Network Resilience Tests (`test/resilience_test.go`)
**Responsibility:**
- **Wi-Fi Disconnect & IP Roaming Simulation**:
  - Node A and Node B active; simulate Node B disconnecting (close listener / fail pings) -> verify `PresenceMonitor` logs offline once.
  - Spin up Node B on a new address/listener and update `Resolver.UpdateFromMDNS` -> verify `PresenceMonitor` logs online once and subsequent clipboard items sync immediately without restarting Node A.
- **Mid-Transfer Abrupt Disconnection (EOF)**:
  - Begin uploading a large payload from client to server, abruptly close the underlying `net.Conn` mid-body.
  - Assert server handles the unexpected `EOF` cleanly, writes 0 bytes to the local clipboard, does not panic, and continues serving subsequent valid requests.
- **Rapid Repeated Copies (TC-06)**:
  - Rapidly write 3 distinct text snippets within `<100ms` on Node A; verify Node B receives and stabilizes on the final snippet without deadlocking.
- **Image-Only Policy Enforcement (TC-07)**:
  - Configure Node A with `ImagesOnly: true`. Node B offers text -> verify Node A responds `action: "skip"`, `reason: "kind_disabled"`, and Node A's clipboard remains unchanged.

---

### Step 4 — Performance & Resource Benchmarks (`test/benchmark_test.go`)
**Responsibility:**
- `BenchmarkSync_Text50KB(b *testing.B)`:
  - Measures end-to-end offer + upload + clipboard apply round-trip for a 50KB UTF-8 text payload; verifies latency well under the 500ms budget.
- `BenchmarkSync_Image5MB(b *testing.B)`:
  - Measures end-to-end offer + PNG validation + streaming upload + clipboard apply for a 5MB PNG image; verifies latency well under the 2.0s budget.
- `TestBenchmark_MemoryStability50Transfers(t *testing.T)`:
  - Records `runtime.MemStats.HeapAlloc` baseline, performs 50 consecutive 1MB+ transfers, calls `runtime.GC()`, and asserts heap growth remains bounded (< 5MB above baseline) with no unbounded buffer retention.

---

### Step 5 — Cross-Platform Build & Documentation Check (`Makefile`, `README.md`)
**Responsibility:**
- Verify `go test -race ./...` passes across all packages with 0 errors.
- Verify cross-compilation succeeds for target release architectures:
  - `GOOS=darwin GOARCH=arm64 go build ./cmd/clipdrop`
  - `GOOS=darwin GOARCH=amd64 go build ./cmd/clipdrop`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/clipdrop`
- Audit `README.md` to ensure installation, pairing, and usage instructions are clear, accurate, and executable in under 10 steps.

---

### Step 6 — Physical Cross-Platform Execution & Sign-Off (macOS ↔ Windows)
**Responsibility (Manual Hardware Verification):**
- Execute physical test matrix on Mac (macOS 14+) and Windows (Windows 11, Private network profile) over shared Wi-Fi:
  - **TC-01**: `clipdrop pair` (Mac) ↔ `clipdrop pair join` (Windows) completes in < 15s.
  - **TC-02**: Mac screenshot (`Cmd+Ctrl+Shift+4`) pastes in Windows Paint in < 2.0s, 0 echo.
  - **TC-03**: Windows screenshot (`Win+Shift+S`) pastes in macOS Preview in < 2.0s, 0 echo.
  - **TC-04**: Bidirectional text sync pastes in < 0.5s, 0 echo.
  - **TC-05**: 10-minute continuous echo audit (30 mixed copies, 0 duplicate/echo logs).
  - **TC-06 / TC-07 / TC-08**: Rapid triple copy, `--images-only`, and `clipdrop unpair` TLS rejection.
  - **Network Recovery**: Wi-Fi toggle IP change + macOS sleep/wake recovery within 5 seconds.
  - **Diagnostics & Retention**: `clipdrop doctor` passes on both machines; `received/` folder caps at 20 files.

---

## Acceptance Criteria Checklist

- [ ] `go test -race ./...` passes with zero race conditions and zero errors across all packages.
- [ ] `test/concurrency_test.go` verifies zero goroutine leaks after 100 transfers and clean 3-second teardown.
- [ ] `test/security_test.go` verifies rogue TLS rejection, HTTP 422 tampering, HTTP 400 spoofed PNG, HTTP 413 oversized stream, and PAKE lockout.
- [ ] `test/resilience_test.go` verifies IP roaming, mid-transfer EOF recovery, rapid triple copy stabilization, and `--images-only` enforcement.
- [ ] `test/benchmark_test.go` verifies 50KB text (< 500ms), 5MB image (< 2.0s), and bounded heap growth across 50 transfers.
- [ ] Cross-platform builds succeed for `darwin/arm64`, `darwin/amd64`, and `windows/amd64`.
- [ ] `README.md` provides complete setup instructions in under 10 steps.
- [ ] Physical macOS ↔ Windows test matrix (TC-01 to TC-08) and 10-minute echo audit signed off.
