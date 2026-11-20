# Phase 1 — Implementation Plan

## Overview

This document translates the Phase 1 specification into a concrete, file-by-file build sequence. Work is ordered so that every step compiles cleanly before the next begins. No clipboard, network, or crypto code is introduced here.

**Files to create in Phase 1:**

```
config/
  config.go          — Dir resolution, defaults, permission enforcement
app/
  app.go             — Application runner, context, signal handling
  commands.go        — Stub handlers for every subcommand
cmd/clipdrop/
  main.go            — Entry point, subcommand router, FlagSets
```

**Total: 4 files. All standard library. Zero external imports.**

---

## Step 1 — `config/config.go`

**What it holds:**
- A `Config` struct carrying all runtime settings (port, peer address, flags, paths).
- A `Defaults()` function returning a fully populated `Config` with safe defaults.
- A `Dir()` function returning the platform-correct config directory path using `os.UserConfigDir()`.
- An `EnsureDir()` function that creates the directory if it does not exist, enforcing mode `0700`.
- A `CheckPerms()` function that reads directory permissions and warns if they are wider than `0700`.

**Default values to hardcode:**
- `Port`: `47820`
- `MaxImageBytes`: `26_214_400` (25 MB)
- `MaxTextBytes`: `1_048_576` (1 MB)
- `HeartbeatInterval`: `5 * time.Second`
- `ConnectTimeout`: `3 * time.Second`
- `OfferTimeout`: `3 * time.Second`
- `UploadTimeout`: `15 * time.Second`
- `DeviceName`: resolved at runtime from `os.Hostname()`

**Platform path logic inside `Dir()`:**
- Call `os.UserConfigDir()` — Go handles the OS differences automatically.
- Append `"clipdrop"` as a subdirectory.
- The result is:
  - macOS → `~/Library/Application Support/clipdrop`
  - Windows → `%AppData%\Roaming\clipdrop`
  - Linux → `~/.config/clipdrop`

**Permission check inside `CheckPerms()` (Unix only):**
- Use `os.Stat()` to get `FileInfo`.
- Extract mode bits using `.Mode().Perm()`.
- If the value is wider than `0700` (i.e., group or world bits are set), emit a `slog.Warn`.
- On Windows, skip silently — Windows uses ACLs not Unix mode bits.

**Testing this file:**
- Test that `Dir()` returns a path ending in `"clipdrop"`.
- Test that `EnsureDir()` creates the directory with `0700` permissions.
- Test that `CheckPerms()` triggers a warning when permissions are `0755`.

---

## Step 2 — `app/app.go`

**What it holds:**
- An `App` struct that owns the root `context.Context` and `context.CancelFunc`.
- A `New(cfg *config.Config) *App` constructor.
- A `Run(ctx context.Context, handler func(context.Context) error) error` method that:
  1. Creates a child context with `signal.NotifyContext` listening for `os.Interrupt` and `syscall.SIGTERM`.
  2. Calls the provided handler function with that context.
  3. When the handler returns (or the signal arrives), allows up to 3 seconds for in-flight work to finish using a drain timer.
  4. Returns any error from the handler.
- A `shutdown()` helper that logs `"shutting down…"` and starts the drain timer.

**Key behaviors:**
- Signal arrives → context cancels → handler sees `ctx.Done()` closed → handler returns → `Run` exits cleanly with code 0.
- Handler returns an error → `Run` propagates it up → `main` logs it and exits with code 1.
- The 3-second shutdown budget is a `time.NewTimer`, not `time.Sleep`. It fires concurrently and forces an exit only if the handler is hanging.

**Testing this file:**
- Test that `Run` calls the handler exactly once.
- Test that simulating a cancelled context causes `Run` to return promptly.

---

## Step 3 — `app/commands.go`

**What it holds:**
Stub handler functions — one per subcommand. Each accepts `(ctx context.Context, cfg *config.Config)` and returns `error`. In Phase 1, each stub simply logs that it was invoked using `slog` and returns `nil`. They will be replaced with real implementations in later phases.

**Stubs to create:**

| Function Name | Logs On Entry | Eventual Phase |
|---|---|---|
| `RunSync` | `"run: starting sync daemon (not yet implemented)"` | Phase 4 |
| `RunPairHost` | `"pair: starting host pairing mode (not yet implemented)"` | Phase 4 |
| `RunPairJoin` | `"pair join: starting joiner mode (not yet implemented)"` | Phase 4 |
| `RunDevices` | `"devices: listing trusted peers (not yet implemented)"` | Phase 4 |
| `RunUnpair` | `"unpair: revoking trust (not yet implemented)"` | Phase 4 |
| `RunDoctor` | `"doctor: running diagnostics (not yet implemented)"` | Phase 5 |
| `PrintVersion` | *(no log — prints to stdout directly)* | Phase 1 |

**Version output format for `PrintVersion`:**
```
clipdrop version dev
protocol version 1
built with go1.27.4
```
Version, commit, and build date are injected via linker flags (`-ldflags`) at compile time, with `"dev"` as the fallback when building locally without flags.

**Package-level variables for version injection:**
```
var (
    Version   = "dev"
    Commit    = "none"
    BuildDate = "unknown"
)
```
These are the linker flag targets — no other mechanism needed.

---

## Step 4 — `cmd/clipdrop/main.go`

This is the entry point. It does exactly three things: parse the top-level subcommand, set up logging, and dispatch to `app/commands.go`. Zero business logic lives here.

### 4.1 Logger Initialization

Before any argument parsing, the program reads whether `--verbose` appears anywhere in `os.Args`. Based on that:
- `--verbose` present → `slog.SetDefault` with a handler at `DEBUG` level.
- absent → `slog.SetDefault` with a handler at `INFO` level.

The handler writes to `os.Stderr` using `slog.NewTextHandler`.

### 4.2 Subcommand Router Structure

The router reads `os.Args[1]` and branches into a `switch` statement:

```
os.Args[1] == "version"     → PrintVersion()
os.Args[1] == "run"         → parse run FlagSet → RunSync()
os.Args[1] == "pair"        → check os.Args[2] == "join"? → RunPairJoin() : RunPairHost()
os.Args[1] == "devices"     → RunDevices()
os.Args[1] == "unpair"      → validate os.Args[2] exists → RunUnpair()
os.Args[1] == "doctor"      → RunDoctor()
default                     → printUsage() → os.Exit(2)
```

No arg → `printUsage()` → `os.Exit(2)`.

### 4.3 FlagSet Definitions (one per subcommand)

Each subcommand gets its own `flag.NewFlagSet` to prevent flags leaking across commands:

**`run` FlagSet:**
- `--images-only` bool (default: `false`)
- `--no-text` bool (default: `false`)
- `--port` int (default: `47820`)
- `--peer` string (default: `""`)
- `--verbose` bool (default: `false`)

**`pair` FlagSet:**
- `--port` int (default: `47820`)
- `--verbose` bool (default: `false`)

**`pair join` FlagSet:**
- `--addr` string (default: `""`)
- `--verbose` bool (default: `false`)

**`devices` FlagSet:**
- `--verbose` bool (default: `false`)

**`doctor` FlagSet:**
- `--verbose` bool (default: `false`)

**`unpair` FlagSet:**
- Reads remaining args after FlagSet parse; `os.Args[2]` is the device name.

### 4.4 Error Handling at Top Level

```
main() wraps everything in a run() function that returns an error.
If run() returns nil   → os.Exit(0)
If run() returns error → slog.Error(err.Error()) → os.Exit(1)
Flag parse failure     → os.Exit(2)
Unknown subcommand     → printUsage() → os.Exit(2)
```

### 4.5 `printUsage()` Output

Printed to `os.Stderr` on unknown subcommands or missing arguments:
```
Usage: clipdrop <command> [flags]

Commands:
  version           print version and protocol information
  run               start clipboard sync in the foreground
  pair              generate a pairing code (host side)
  pair join         join using a pairing code (joiner side)
  devices           list trusted paired devices
  unpair <name>     remove a paired device
  doctor            run system diagnostics

Run 'clipdrop <command> --help' for command-specific flags.
```

---

## Step 5 — Makefile Targets

Add minimal Makefile targets to standardize build commands:

| Target | Command | Purpose |
|---|---|---|
| `make build` | `go build -o clipdrop ./cmd/clipdrop` | Build binary for local OS |
| `make run` | `go run ./cmd/clipdrop` | Run without compiling |
| `make test` | `go test -race ./...` | Run all tests with race detector |
| `make version` | `go build -ldflags "-X main.Version=v0.1.0 ..." ...` | Build with version injected |
| `make clean` | `rm -f clipdrop clipdrop.exe` | Remove compiled outputs |

---

## Step 6 — Unit Test Files

Create one test file per package using `_test.go` suffix:

**`config/config_test.go`**
- Test `Dir()` returns a path that ends in `"clipdrop"`.
- Test `EnsureDir()` creates the dir and stat confirms `0700` permissions.
- Test `Defaults()` returns port `47820`, max image `26214400`, max text `1048576`.

**`app/app_test.go`**
- Test `Run()` with a handler that returns immediately — verify no error.
- Test `Run()` with a handler that respects context cancellation — verify clean exit.

**`cmd/clipdrop` — no unit tests** (integration via manual acceptance scenarios).

---

## Build & Verification Sequence

Execute in this order after all 4 files are written:

1. `go build ./...` — must compile with zero errors.
2. `./clipdrop version` — prints version block, exits 0.
3. `./clipdrop` — prints usage, exits 2.
4. `./clipdrop run --verbose` — logs "not yet implemented" at DEBUG level.
5. `./clipdrop run` then `Ctrl+C` — logs shutdown, exits 0.
6. `./clipdrop run --invalid-flag` — prints flag error, exits 2.
7. `go test -race ./...` — zero failures, zero race warnings.
8. Confirm config dir created at correct OS path with mode `0700`.
