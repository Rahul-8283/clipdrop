# Phase 2 — Implementation Plan: Local Core (Clipboard, Imaging & Engine)

## Overview

This document translates the Phase 2 specification ([docs/2_v1.md](file:///Users/rahulls/Projects/Screenshot_Sync/Clipdrop/docs/2_v1.md)) into a concrete step-by-step build sequence. 

In this phase, we build the core local pipeline:
1. **Clipboard abstraction** (`platform/clipboard`): A clean interface with a real implementation using `golang.design/x/clipboard` and an in-memory test double (`FakeClipboard`).
2. **Payload validation** (`imaging`): High-speed byte-level validation for PNG screenshots (magic bytes, IHDR chunk dimensions <= 16k x 16k, and size <= 25MB).
3. **Core synchronization engine** (`engine`): Change detection, content hashing (SHA-256), deduplication, and the critical **Echo Loop Prevention** state machine.
4. **Wiring into `app`**: Connecting the clipboard watcher to the engine so `clipdrop run` logs local clipboard changes without network transfer.
5. **Testing** (`test/`): Deterministic unit tests with `FakeClipboard` verifying zero echo loops and strict deduplication under `go test -race`.

---

## File Architecture for Phase 2

```
platform/clipboard/
  clipboard.go        — Clipboard interface, Item struct, ItemKind ("image"|"text")
  clipboard_real.go   — Real OS wrapper using golang.design/x/clipboard
  clipboard_fake.go   — In-memory fake clipboard with event channels for testing
imaging/
  png.go              — PNG magic signature, IHDR chunk dimension extractor, limits
engine/
  hash.go             — SHA-256 computation utility for byte payloads
  state.go            — Thread-safe store for LastReceivedHash and LastLocalSentHash
  engine.go           — Event loop, outbound filter (dedupe + echo suppression), inbound applier
test/
  clipboard_test.go   — Tests for FakeClipboard contracts (Read, Write, Watch)
  imaging_test.go     — Tests for PNG signature check, dimensions, corrupted chunks, size limits
  engine_test.go      — Tests verifying echo loop prevention, dedupe, and flag filtering
```

---

## Step-by-Step Implementation Sequence

### Step 1 — `platform/clipboard/clipboard.go`
**Responsibility:**
- Define `ItemKind` enum/type: `KindText` ("text") and `KindImage` ("image").
- Define `Item` struct:
  - `Kind` (`ItemKind`)
  - `Data` (`[]byte`)
  - `Mime` (`string`: "image/png" or "text/plain; charset=utf-8")
- Define `Clipboard` interface:
  - `Read() (*Item, error)`
  - `Write(item *Item) error`
  - `Watch(ctx context.Context) <-chan struct{}`
- Define common errors (`ErrEmpty`, `ErrUnsupportedFormat`, `ErrUnavailable`).

---

### Step 2 — `platform/clipboard/clipboard_fake.go`
**Responsibility:**
- Provide `FakeClipboard` struct implementing `Clipboard`.
- Backed by an in-memory `sync.RWMutex`, storing current `*Item`.
- Maintains a slice of subscriber notification channels.
- `Write(item)` updates memory and non-blockingly notifies watchers.
- `Read()` returns a copy of current item or `ErrEmpty`.
- `Watch(ctx)` returns a channel emitting events when `Write()` is called, closing upon context cancellation.
- Exposes `TriggerChange()` for tests to simulate external OS pasteboard modifications.

---

### Step 3 — `platform/clipboard/clipboard_real.go`
**Responsibility:**
- Wraps `golang.design/x/clipboard`.
- Initialize clipboard subsystem on construction via `clipboard.Init()`.
- `Read()`: First attempts `clipboard.Read(clipboard.FmtImage)`. If present and non-empty, returns `KindImage` (PNG). Otherwise attempts `clipboard.Read(clipboard.FmtText)`.
- `Write(item)`: Writes to OS clipboard using `clipboard.Write(FmtImage, data)` or `FmtText`.
- `Watch(ctx)`: Merges native watcher channels from `clipboard.Watch(ctx, FmtImage)` and `clipboard.Watch(ctx, FmtText)` into a unified event stream.
- Handles OS retry/backoff for clipboard read locks (especially on Windows).

---

### Step 4 — `imaging/png.go`
**Responsibility:**
- Validates raw PNG byte slices without decoding full pixel raster scans into RAM.
- Verifies 8-byte PNG magic header: `\x89PNG\r\n\x1a\n`.
- Locates and extracts the `IHDR` chunk:
  - Validates big-endian 32-bit `Width` and `Height`.
  - Enforces guardrails: Width and Height must be `> 0` and `<= 16384`.
- Validates maximum byte size (`MaxImageBytes = 26,214,400`, 25MB).
- Returns descriptive errors for truncated files, bad magic numbers, or excessive dimensions.

---

### Step 5 — `engine/hash.go` & `engine/state.go`
**Responsibility:**
- `hash.go`:
  - `ComputeHash(data []byte) string`: Returns lowercase hex SHA-256 digest.
- `state.go`:
  - `SyncState` struct guarded by `sync.RWMutex`:
    - `lastReceivedHash string`: Hash of item received from peer and written to OS.
    - `lastSentHash string`: Hash of item dispatched outbound.
  - Thread-safe getters and setters (`SetLastReceived`, `IsLastReceived`, `SetLastSent`, `IsLastSent`).

---

### Step 6 — `engine/engine.go`
**Responsibility:**
- Core engine coordinator connecting the clipboard watcher to data evaluation.
- Implements **Outbound Evaluation Pipeline**:
  1. Watcher signals clipboard change.
  2. Reads clipboard item (`clipboard.Read()`).
  3. Checks policy: if text and `--images-only` / `--no-text` is active, drop.
  4. Validates payload (`imaging.ValidatePNG` or UTF-8 check).
  5. Computes SHA-256 hash.
  6. **Echo Check**: if `hash == state.LastReceivedHash`, drop immediately (suppress echo!).
  7. **Dedupe Check**: if `hash == state.LastSentHash`, drop (user copied same item twice).
  8. Updates `state.LastSentHash`.
  9. Emits validated event to outbound handler/channel (logged at INFO in Phase 2).
- Implements **Inbound Apply Contract**:
  - `ApplyInbound(item *Item, hash string)`:
    1. Sets `state.LastReceivedHash = hash` **before** writing.
    2. Calls `clipboard.Write(item)`.

---

### Step 7 — Wire to `app/` and `cmd/clipdrop`
**Responsibility:**
- Update `app.RunSync`:
  - Initialize real clipboard (`clipboard_real.go`).
  - Initialize engine with active `Config`.
  - Start engine event loop in background.
  - On clipboard change, log item details: `slog.Info("clipboard event", "kind", item.Kind, "size", len(item.Data), "hash", hash)`.
  - Gracefully stops on `ctx.Done()`.

---

### Step 8 — Comprehensive Testing in `test/`
**Test Suites:**
1. `test/clipboard_test.go`: Verify `FakeClipboard` `Read`, `Write`, and `Watch` cancelation.
2. `test/imaging_test.go`:
   - Valid minimal PNG (Passes).
   - Non-PNG / JPEG magic bytes (Fails).
   - Zero dimensions or > 16k dimensions (Fails).
   - Truncated bytes / Corrupted IHDR (Fails).
   - > 25MB payload (Fails).
3. `test/engine_test.go`:
   - **Echo Suppression Test**: Call `ApplyInbound`, trigger clipboard watcher, assert outbound pipeline emits 0 events.
   - **Dedupe Test**: Trigger same copy twice, assert 1 emission and 1 suppression.
   - **Policy Test**: `--images-only` drops text copies, allows PNG copies.
   - **Race Condition Test**: Concurrent fake copies and inbound applies tested with `go test -race`.

---

## Acceptance Criteria Checklist

- [ ] All code strictly adheres to package boundaries (no `internal/`).
- [ ] No external dependencies added beyond `golang.design/x/clipboard`.
- [ ] 100% test pass rate with `go test -race -v ./test/...`.
- [ ] Manual test on Mac: Taking a screenshot (`Cmd+Ctrl+Shift+4`) while running `./clipdrop run` logs PNG detection, dimension, and hash.
