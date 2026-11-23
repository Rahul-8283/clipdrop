# Phase 4 — Implementation Plan: Discovery, Pairing & Sync Pipeline

## Overview

This document translates the Phase 4 specification ([docs/4_v1.md](file:///Users/rahulls/Projects/Screenshot_Sync/Clipdrop/docs/4_v1.md)) into a concrete step-by-step build sequence.

In Phase 4, we connect the cryptographic identity, secure transport, and clipboard engine into a fully autonomous, peer-to-peer synchronization system:
1. **Out-of-Band PAKE Pairing** (`netx/pairing/`): Short phonetic code generation (`NNNN-word-word`), ephemeral HTTP server with 120s expiration and 3-attempt brute-force lockout, PAKE key exchange (`schollz/pake/v3`), and AES-GCM identity exchange.
2. **Device Trust Management Commands** (`app/commands.go`): Listing paired devices (`clipdrop devices`) and revoking peer trust (`clipdrop unpair <name>`).
3. **Local mDNS Discovery & Routing** (`netx/discovery/`): Publishing and browsing `_clipdrop._tcp` records via `grandcat/zeroconf`, parsing TXT attributes, and resolving peer addresses using a 3-tier priority hierarchy (mDNS > `--peer` override > stored last address).
4. **Presence & Heartbeat Monitoring** (`app/presence.go`): 5-second background health checks via `GET /v1/ping`, tracking online/offline state transitions with clean edge-triggered logging.
5. **Unified Sync Pipeline** (`app/sync.go`, `app/commands.go`): Coordinating clipboard watchers, engine filters, discovery resolvers, and mTLS transport pipelines into a complete bidirectional synchronization loop.
6. **Comprehensive Automated Tests** (`test/`): In-memory PAKE sessions, lockout mechanisms, discovery routing tables, presence state machines, and end-to-end sync loop tests.

---

## File Architecture for Phase 4

```
netx/
  pairing/
    code.go            — Dictionary-based code generator (NNNN-word-word) and normalizer
    pake.go            — Wrapper for schollz/pake v3 CurveP256 handshake & session key derivation
    credentials.go     — Identity payload model and AES-256-GCM authenticated encryption
    host.go            — Ephemeral HTTP pairing server, 120s timer, 3-attempt brute-force lockout
    joiner.go          — Pairing client, mDNS pairing locator, PAKE negotiator, trust registration
  discovery/
    record.go          — Service constants (_clipdrop._tcp), TXT record schema, instance naming
    announcer.go       — Zeroconf mDNS service publisher (status: "ready" vs "pairing")
    browser.go         — Zeroconf mDNS service browser, TXT record decoder, peer filtering
    resolver.go        — In-memory routing table mapping DeviceID -> IP:Port with 3-tier fallback
app/
  presence.go          — 5-second health ping ticker, online/offline edge-triggered logging
  sync.go              — Unified bidirectional event sync pipeline orchestrator
  commands.go          — Implementations for pair, pair join, devices, unpair, and updated run
test/
  pairing_test.go      — Code generation, PAKE key derivation, attempt lockout, 120s expiration
  discovery_test.go    — TXT record decoding, routing table management, 3-tier address resolution
  presence_test.go     — Online/offline edge detection, clean logging, store timestamp updates
  sync_test.go         — Multi-node end-to-end sync loop, echo suppression, offline peer handling
```

---

## Step-by-Step Implementation Sequence

### Step 1 — `netx/pairing/code.go` & `netx/pairing/pake.go`
**Responsibility:**
- `code.go`:
  - Curated, clean, phonetic English word list (e.g., 256 common animals, colors, natural elements).
  - Generator: creates `NNNN-word-word` format (e.g. `8412-amber-falcon`) using `crypto/rand` for the 4-digit number and word indices.
  - Normalizer: trims whitespace and lowercases input codes for tolerant user entry.
- `pake.go`:
  - Implements `Session` wrapping `schollz/pake/v3`.
  - Uses `pake.CurveP256()`.
  - Roles: `RoleHost` (party `A`) and `RoleJoiner` (party `B`).
  - `InitHost(code string) (*Session, []byte, error)`: creates host session, returns initial public point `A`.
  - `InitJoiner(code string, pointA []byte) (*Session, []byte, error)`: creates joiner session, ingests `A`, returns point `B`.
  - `CompleteHost(s *Session, pointB []byte) ([]byte, error)`: ingests `B`, verifies handshake, derives 32-byte symmetric key.
  - `SessionKey(s *Session) ([]byte, error)`: retrieves derived 32-byte session key on joiner.

---

### Step 2 — `netx/pairing/credentials.go`
**Responsibility:**
- Define `Credentials` payload exchanged between peers:
  ```go
  type Credentials struct {
      DeviceID string `json:"device_id"` // Lowercase hex SHA-256 fingerprint
      Name     string `json:"name"`      // Device hostname
      OS       string `json:"os"`        // Operating system ("darwin", "windows", "linux")
  }
  ```
- Symmetric authenticated encryption using `crypto/cipher` (AES-256-GCM):
  - `EncryptCredentials(creds *Credentials, key []byte) ([]byte, error)`:
    - Serializes `Credentials` to JSON.
    - Generates 12-byte cryptographically random nonce.
    - Encrypts and authenticates with AES-GCM; prepends nonce to ciphertext.
  - `DecryptCredentials(ciphertext []byte, key []byte) (*Credentials, error)`:
    - Extracts 12-byte nonce.
    - Decrypts and authenticates ciphertext with AES-GCM.
    - Deserializes and validates `Credentials` (rejecting empty ID or Name).

---

### Step 3 — `netx/pairing/host.go` & `netx/pairing/joiner.go`
**Responsibility:**
- `host.go`:
  - Define `Host` managing the ephemeral HTTP pairing server on a dynamic port (`:0`).
  - Ephemeral endpoints:
    - `POST /v1/pair/pake`: receives joiner's point `B`, returns HTTP 200 with status (or failure).
    - `POST /v1/pair/exchange`: receives encrypted joiner credentials, returns host's encrypted credentials.
  - Guardrails:
    - Session expiration: context with 120-second timeout.
    - Brute-force lockout: atomic attempt counter; on 3 consecutive cryptographic failures, halts listener and returns error.
    - Single-use guarantee: upon successful exchange, writes peer to `store.Store`, shuts down listener, and halts mDNS broadcast.
  - Callback: notifies caller when pairing succeeds with peer metadata.
- `joiner.go`:
  - Define `Join` function taking target host address (`ip:port`), entered code, local `Identity`, and `Store`.
  - Executes HTTP requests to `/v1/pair/pake` and `/v1/pair/exchange`.
  - Decrypts host identity, writes host to `store.Store`, and returns paired device metadata.

---

### Step 4 — Device Trust Management Commands (`app/commands.go`)
**Responsibility:**
- `RunDevices(ctx context.Context, cfg *config.Config) error`:
  - Loads `store.New(filepath.Join(cfg.ConfigDir, "trusted_devices.json"))`.
  - Calls `store.List()`.
  - If empty, prints `"No paired devices. Run 'clipdrop pair' to link a peer."`.
  - Otherwise, outputs a formatted CLI table:
    - Column headers: `NAME`, `OS`, `DEVICE ID`, `PAIRED`, `LAST SEEN`, `LAST ADDRESS`.
    - Truncates Device ID to first 16 characters for readable display (or full hex if `--verbose`).
    - Formats timestamps cleanly (e.g. `2 minutes ago`, `Yesterday`, or RFC3339).
- `RunUnpair(ctx context.Context, cfg *config.Config) error`:
  - Validates `os.Args` has target identifier (`name` or `deviceID`).
  - Searches `store.List()` by exact name or device ID match.
  - If not found, prints remediation error and exits with code 1.
  - Calls `store.Remove(target.ID)`.
  - Prints: `"Revoked trust for [name] ([truncated-id])."`.

---

### Step 5 — `netx/discovery/` (mDNS Zeroconf Registration & Resolution)
**Responsibility:**
- `record.go`:
  - Service type: `ServiceType = "_clipdrop._tcp"`, domain: `Domain = "local."`.
  - Status constants: `StatusReady = "ready"`, `StatusPairing = "pairing"`.
  - Instance name builder: `<first-16-fingerprint>-<hostname>`.
  - TXT record builder & parser: `id`, `name`, `os`, `proto`, `status`.
- `announcer.go`:
  - Wraps `zeroconf.Register`.
  - Method `Announce(ctx context.Context, ident *identity.Identity, port int, status string) (*Announcer, error)`.
  - Method `SetStatus(status string) error`: updates TXT record between `"ready"` and `"pairing"`.
  - Method `Shutdown()`: unregisters mDNS entry cleanly on process stop.
- `browser.go`:
  - Wraps `zeroconf.Browse`.
  - Continuously listens for `_clipdrop._tcp` announcements on local subnet.
  - Parses incoming service entries and extracts TXT attributes and IPv4/IPv6 addresses.
  - Updates the routing table in `resolver.go`.
- `resolver.go`:
  - Thread-safe `Resolver` maintaining in-memory mapping: `map[string]*PeerAddress` (`IP`, `Port`, `LastSeen`).
  - 3-tier address resolution hierarchy:
    1. Active mDNS discovered IP and port (freshest live network state).
    2. CLI `--peer ip:port` override from `config.Config` (if provided).
    3. Stored `LastAddress` from `trusted_devices.json`.
  - Returns best address or `ErrPeerOffline` if all 3 tiers yield no reachable endpoint.

---

### Step 6 — Peer Presence & Heartbeat Monitoring (`app/presence.go`)
**Responsibility:**
- Define `PresenceMonitor` struct:
  - Backed by `config.Config`, `store.Store`, `transport.Client`, and `discovery.Resolver`.
  - Maintains `map[string]bool` tracking `online` status per device ID.
- Heartbeat loop:
  - Runs on a 5-second `time.Ticker` until `ctx.Done()`.
  - For each device in `store.List()`:
    - Resolves network address via `resolver.Resolve(dev.ID)`.
    - If unresolvable, marks offline.
    - If address available, calls `client.Ping(pingCtx, addr)`.
    - If ping succeeds:
      - If previously offline: logs `slog.Info("peer is online", "name", dev.Name, "addr", addr)`.
      - Updates `online = true`.
      - Calls `store.UpdateLastSeen(dev.ID, addr)`.
    - If ping fails:
      - If previously online: logs `slog.Info("peer went offline", "name", dev.Name)`.
      - Updates `online = false`.
  - Edge-triggered logging guarantee: steady-state successes or failures produce zero log output.

---

### Step 7 — CLI Pairing Commands (`app/commands.go`)
**Responsibility:**
- `RunPairHost(ctx context.Context, cfg *config.Config) error`:
  - Loads identity and store from `cfg.ConfigDir`.
  - Starts ephemeral pairing host (`pairing.NewHost(...)`) on dynamic port.
  - Publishes mDNS pairing advertisement with `status=pairing`.
  - Displays pairing code banner in terminal:
    ```text
    ==================================================
      Pairing Code:  8412-amber-falcon
      Expires in:    2 minutes
      Waiting for peer to join...
    ==================================================
    ```
  - Waits for incoming joiner or 120s timeout.
  - On success: logs `"Paired with [peer-name]"`, stops mDNS pairing broadcast, and exits cleanly.
- `RunPairJoin(ctx context.Context, cfg *config.Config) error`:
  - Prompts operator: `"Enter pairing code: "` (or reads from CLI argument if provided).
  - Discovers host advertising `status=pairing` via mDNS (or uses `--addr` flag fallback).
  - Connects to host, executes PAKE point exchange and AES-GCM credential swap.
  - On success: logs `"Paired with [peer-name]"` and saves host to `trusted_devices.json`.

---

### Step 8 — Unified End-to-End Sync Pipeline (`app/sync.go` & `app/commands.go`)
**Responsibility:**
- Update `app.RunSync`:
  - Initializes all 5 core subsystems under root cancellation context:
    1. Real or Fake Clipboard watcher (`platform/clipboard`).
    2. Engine outbound detection and inbound apply pipeline (`engine.Engine`).
    3. mTLS sync server on `cfg.Port` (`transport.NewServer`).
    4. mDNS announcer broadcasting `_clipdrop._tcp` with `status=ready` (`discovery.NewAnnouncer`).
    5. mDNS browser and routing table resolver (`discovery.NewBrowser`, `discovery.NewResolver`).
    6. Presence monitor with 5-second heartbeat loop (`app.NewPresenceMonitor`).
    7. Outbound dispatch worker:
       - Consumes events from `engine.Outbound()`.
       - Queries `resolver.OnlinePeers()`.
       - If no peers reachable: logs `slog.Debug("peer offline, item dropped")`.
       - For each reachable peer:
         - Sends pre-flight `client.Offer(ctx, addr, req)`.
         - If `resp.Action == "skip"`: logs skip reason and skips upload.
         - If `resp.Action == "send"`: streams payload via `client.Upload(ctx, addr, id, data, kind, mime, hash)`.
         - On HTTP 200: logs `slog.Info("sent clipboard item", "kind", item.Kind, "size", len(item.Data), "peer", peer.Name)`.
  - Signal handling: gracefully terminates all 5 routines within 3-second shutdown budget.

---

### Step 9 — Comprehensive Test Suites in `test/`
**Test Suites:**
1. `test/pairing_test.go`:
   - Code generation format: verify `NNNN-word-word` pattern and dictionary validity.
   - PAKE key derivation: verify identical symmetric keys derived when codes match.
   - PAKE failure: verify cryptographic failure when codes do not match.
   - AES-GCM credentials encryption and decryption round-trip.
   - Attempt lockout: verify ephemeral host listener closes and rejects after 3 failed attempts.
   - Session expiration: verify ephemeral host times out after expiration budget.
2. `test/discovery_test.go`:
   - TXT record serialization & deserialization (`id`, `name`, `os`, `proto`, `status`).
   - Resolver 3-tier hierarchy: verify active mDNS address takes precedence over `--peer` and store `LastAddress`.
   - Dynamic status update: verify switching between `"ready"` and `"pairing"` updates record.
3. `test/presence_test.go`:
   - Online/offline edge detection: verify transition logs trigger exactly once on status flip.
   - Store update: verify successful heartbeat advances `LastSeen` and updates `LastAddress`.
4. `test/sync_test.go`:
   - Two-Node full sync loop:
     - Node A copies image -> Node B receives, verifies PNG, applies to clipboard.
     - Verify zero echo loops (Node B does not re-offer item back to Node A).
     - Node B copies text -> Node A receives and applies.
   - Offline peer handling:
     - Item copied when peer is offline is dropped without hanging routines.
     - When peer comes online, new copies sync immediately.

---

## Acceptance Criteria Checklist

- [x] Phonetic pairing code adheres to `NNNN-word-word` format.
- [x] Ephemeral pairing server enforces 120-second timeout and 3-attempt brute-force lockout.
- [x] PAKE handshake uses `schollz/pake/v3` with Curve P-256 and AES-256-GCM.
- [ ] `clipdrop pair` and `clipdrop pair join` successfully link two nodes and write mutually trusted records.
- [x] `clipdrop devices` prints formatted table of paired peers.
- [x] `clipdrop unpair <name>` immediately revokes peer trust.
- [x] mDNS discovery broadcasts and browses `_clipdrop._tcp` records using `grandcat/zeroconf`.
- [x] Address resolver strictly enforces 3-tier hierarchy (mDNS > `--peer` > store `LastAddress`).
- [ ] Presence monitor polls every 5s with edge-triggered online/offline logging.
- [ ] Complete sync loop delivers clipboard items bidirectionally in under 2 seconds.
- [ ] Echo suppression prevents ping-pong loops across nodes.
- [ ] All unit, loopback, and integration tests pass with `go test -race -v ./test/...`.
- [ ] Binary compiles cleanly with `make build`.
