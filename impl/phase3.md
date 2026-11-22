# Phase 3 — Implementation Plan: Identity & Transport Security

## Overview

This document translates the Phase 3 specification ([docs/3_v1.md](file:///Users/rahulls/Projects/Screenshot_Sync/Clipdrop/docs/3_v1.md)) into a concrete step-by-step build sequence.

In this phase, we establish decentralized cryptographic identity, pinned certificate trust, and mutual TLS 1.3 (mTLS) HTTP transport:
1. **Device Identity** (`identity/`): Generating ECDSA P-256 keypairs, self-signed X.509 v3 certificates, deriving SHA-256 fingerprints, and storing them with strict `0600` permissions.
2. **Trusted Devices Store** (`store/`): Managing `trusted_devices.json` with thread-safe atomic file writes and instant revocation.
3. **Mutual TLS 1.3 Configuration** (`netx/transport/tls.go`): Custom certificate-pinning TLS configuration for both server and client without external Certificate Authorities.
4. **Transport Protocol & HTTP Server** (`netx/transport/server.go`): Handlers for `GET /v1/ping`, `POST /v1/offer`, and streaming `PUT /v1/items/{id}` with size and hash verifications.
5. **Transport Client** (`netx/transport/client.go`): Hardened HTTP client executing mTLS handshakes, health pings, offers, and uploads.
6. **Integration & Concurrency Tests** (`test/`): In-process localhost two-node transfers, rogue intruder handshake rejection, payload tampering checks, and race condition audits.

---

## File Architecture for Phase 3

```
identity/
  identity.go        — Keypair generation, X.509 cert creation, fingerprinting, 0600 persistence
store/
  store.go           — trusted_devices.json management, thread-safe atomic JSON persistence
netx/
  transport/
    tls.go           — mTLS 1.3 configuration, pinned fingerprint verification callbacks
    protocol.go      — Protocol headers, request/response models, action/reason constants
    server.go        — mTLS HTTP server, /v1/ping, /v1/offer, /v1/items/{id} endpoints
    client.go        — mTLS HTTP client, Ping, Offer, and Upload streaming methods
test/
  identity_test.go   — Key generation, self-signed cert validation, fingerprint check, 0600 perms
  store_test.go      — Device addition, lookup, update, removal, and atomic file resilience
  transport_test.go  — Two-node localhost mTLS transfer, intruder rejection, hash mismatch, size limit
```

---

## Step-by-Step Implementation Sequence

### Step 1 — `identity/identity.go`
**Responsibility:**
- Define `Identity` struct holding private key (`*ecdsa.PrivateKey`), certificate (`*x509.Certificate`), `DeviceID` (`string`), and `TLSCert` (`tls.Certificate`).
- Key generation: ECDSA NIST P-256 (`elliptic.P256()`).
- Self-signed X.509 certificate generation:
  - 10-year validity window (`time.Now()` to `time.Now().AddDate(10, 0, 0)`).
  - CommonName set to local device hostname.
  - KeyUsage: `DigitalSignature | KeyAgreement`.
  - ExtKeyUsage: `ServerAuth`, `ClientAuth`.
- Device ID derivation: lowercase hexadecimal SHA-256 digest of raw DER certificate bytes (`sha256.Sum256(cert.Raw)`).
- `LoadOrGenerate(configDir string, hostname string) (*Identity, error)`:
  - Checks if `key.pem` and `cert.pem` exist.
  - If existing, validates file permissions (`0600` on Unix), loads and parses PEM blocks.
  - If absent, generates new keypair and certificate, writes them with mode `0600`.

---

### Step 2 — `store/store.go`
**Responsibility:**
- Define `Device` struct:
  - `ID` (string, SHA-256 certificate fingerprint)
  - `Name` (string, hostname)
  - `OS` (string, e.g. "darwin", "windows")
  - `PairedAt` (time.Time)
  - `LastSeen` (time.Time)
  - `LastAddress` (string, e.g. "192.168.1.50:47820")
- Define `Store` struct guarded by `sync.RWMutex`:
  - `filePath string` (pointing to `trusted_devices.json` in config dir).
  - `devices map[string]*Device` (in-memory lookup index).
- Store operations:
  - `New(filePath string) (*Store, error)`: loads existing JSON or creates an empty store.
  - `IsTrusted(deviceID string) bool`: fast lookup for TLS handshake verification.
  - `Get(deviceID string) (*Device, bool)`: retrieves device metadata.
  - `Add(device *Device) error`: inserts or updates a trusted peer and flushes to disk.
  - `UpdateLastSeen(deviceID, address string) error`: updates timestamps and flushes to disk.
  - `Remove(deviceID string) error`: revokes trust and flushes to disk.
  - `List() []*Device`: returns all trusted devices sorted by pairing date.
- Atomic persistence:
  - Marshals JSON with indentation.
  - Writes to temporary file (`trusted_devices.json.tmp`) with mode `0600`.
  - Atomically renames temporary file over destination.

---

### Step 3 — `netx/transport/protocol.go` & `netx/transport/tls.go`
**Responsibility:**
- `protocol.go`:
  - Header constants: `HeaderProtoVersion = "X-Proto-Version"`, `HeaderSha256 = "X-Sha256"`, `ProtoVersion = "1"`.
  - Action constants: `ActionSend = "send"`, `ActionSkip = "skip"`.
  - Skip reason constants: `ReasonDuplicate = "duplicate"`, `ReasonTooLarge = "too_large"`, `ReasonKindDisabled = "kind_disabled"`, `ReasonPaused = "paused"`.
  - Data transfer structures:
    - `PingResponse`: `{ DeviceName string, ProtocolVersion int, CurrentTime string }`.
    - `OfferRequest`: `{ ID string, Kind string, Size int64, Sha256 string, Mime string }`.
    - `OfferResponse`: `{ Action string, Reason string }`.
- `tls.go`:
  - `ServerTLSConfig(ident *identity.Identity, store *store.Store) *tls.Config`:
    - Enforces `MinVersion = tls.VersionTLS13`, `MaxVersion = tls.VersionTLS13`.
    - Sets `Certificates = []tls.Certificate{ident.TLSCert}`.
    - Sets `ClientAuth = tls.RequireAnyClientCert`.
    - Sets custom `VerifyPeerCertificate` callback:
      - Extracts leaf client certificate.
      - Computes SHA-256 fingerprint: `hex.EncodeToString(sha256(rawCert))`.
      - Checks `store.IsTrusted(fingerprint)`.
      - If untrusted, logs warning and returns authentication error to drop the connection immediately.
  - `ClientTLSConfig(ident *identity.Identity, store *store.Store) *tls.Config`:
    - Enforces `MinVersion = tls.VersionTLS13`.
    - Sets `Certificates = []tls.Certificate{ident.TLSCert}`.
    - Sets `InsecureSkipVerify = true` (bypasses default root CA lookup).
    - Sets custom `VerifyPeerCertificate` callback matching server-side fingerprint pinning against `store`.

---

### Step 4 — `netx/transport/server.go`
**Responsibility:**
- Define `Server` struct wrapping `net/http.Server` and a `net.Listener`.
- Constructor: `NewServer(cfg *config.Config, ident *identity.Identity, store *store.Store, eng *engine.Engine) (*Server, error)`.
- Route registration:
  - `GET /v1/ping`:
    - Verifies `X-Proto-Version: 1`.
    - Returns `200 OK` with JSON `PingResponse`.
  - `POST /v1/offer`:
    - Verifies `X-Proto-Version: 1`.
    - Reads and decodes JSON `OfferRequest`.
    - Evaluates skip conditions:
      - If `Kind == "text"` and `--images-only` is active: reply `{"action": "skip", "reason": "kind_disabled"}`.
      - If `Size > MaxImageBytes` or `Size > MaxTextBytes`: reply `{"action": "skip", "reason": "too_large"}`.
      - If `Sha256 == eng.State().CurrentLocalHash()`: reply `{"action": "skip", "reason": "duplicate"}`.
      - Otherwise: reply `{"action": "send"}`.
  - `PUT /v1/items/{id}`:
    - Verifies `X-Proto-Version: 1` and presence of `X-Sha256` header.
    - Streams request body with `io.LimitReader` capped at `MaxImageBytes + 1`.
    - If bytes read exceed limit: respond `413 Payload Too Large`.
    - Computes streaming SHA-256: if mismatch with `X-Sha256`, respond `422 Unprocessable Entity`.
    - If kind is image, calls `imaging.ValidatePNG(data)`: if invalid, respond `400 Bad Request`.
    - Applies payload to clipboard via `eng.ApplyInbound(item, hash)`.
    - Returns `200 OK`.
- Lifecycle methods: `Start() error` and `Stop(ctx context.Context) error`.

---

### Step 5 — `netx/transport/client.go`
**Responsibility:**
- Define `Client` struct wrapping `*http.Client` configured with client-side mTLS 1.3.
- Constructor: `NewClient(ident *identity.Identity, store *store.Store) *Client`.
- Timeouts: Connect timeout (3s), ResponseHeader timeout (3s).
- API Client methods:
  - `Ping(ctx context.Context, addr string) (*PingResponse, error)`:
    - Issues `GET https://{addr}/v1/ping` with `X-Proto-Version: 1`.
  - `Offer(ctx context.Context, addr string, req *OfferRequest) (*OfferResponse, error)`:
    - Issues `POST https://{addr}/v1/offer` with JSON body and `X-Proto-Version: 1`.
  - `Upload(ctx context.Context, addr string, id string, data []byte, kind clipboard.ItemKind, mime string, hash string) error`:
    - Issues `PUT https://{addr}/v1/items/{id}` with raw bytes body.
    - Sets headers: `X-Proto-Version: 1`, `X-Sha256: {hash}`, `Content-Type: {mime}`.
    - Uses 15-second upload timeout.

---

### Step 6 — Comprehensive Tests in `test/`
**Test Suites:**
1. `test/identity_test.go`:
   - Generate new identity: verify P-256 curve, 10-year validity, valid fingerprint.
   - Verify `key.pem` and `cert.pem` are created with `0600` permissions.
   - Reload existing identity from disk: verify loaded key, cert, and fingerprint match generated original.
2. `test/store_test.go`:
   - Add device to store, verify `IsTrusted` returns true for fingerprint.
   - Verify `Get`, `List`, and `UpdateLastSeen`.
   - Remove device, verify `IsTrusted` immediately returns false.
   - Crash/integrity test: verify atomic rename writes valid JSON without data corruption.
3. `test/transport_test.go`:
   - **Two-Node Handshake & Ping Test**: Spawn Server A (port 0) and Server B (port 0) with distinct identities on localhost. Register A in B's store and B in A's store. Client A calls `Ping` on Server B -> passes with 200 OK.
   - **Untrusted Peer Rejection Test**: Spawn Client C with rogue identity not present in Server A's store. Client C calls `Ping` on Server A -> handshake fails and connection is dropped.
   - **Offer & Upload Flow**: Client A offers item X to Server B (`send`), streams payload via `Upload` -> Server B validates hash, validates PNG, calls `ApplyInbound`, returns 200 OK.
   - **Duplicate Offer Test**: Client A offers item with hash matching Server B's clipboard -> Server B replies `skip` (reason: `duplicate`).
   - **Hash Mismatch Rejection**: Client A uploads body with mismatched `X-Sha256` header -> Server B rejects with 422 Unprocessable Entity.
   - **Oversized Stream Rejection**: Client A uploads 26 MB body -> Server B truncates and rejects with 413 Payload Too Large.
   - **Protocol Version Mismatch**: Request with missing or mismatched `X-Proto-Version` -> rejected with 400 Bad Request.

---

## Acceptance Criteria Checklist

- [ ] All cryptographic code uses standard library `crypto/ecdsa`, `crypto/x509`, `crypto/tls`, `crypto/sha256`. No third-party crypto libraries.
- [ ] Strict TLS 1.3 pinning: unlisted certificates are dropped during the TLS handshake.
- [ ] Key and cert files strictly observe `0600` filesystem permissions.
- [ ] Atomic file writes protect `trusted_devices.json` against corruption.
- [ ] All unit and loopback integration tests pass with `go test -race -v ./test/...`.
- [ ] Binary compiles cleanly with `make build`.
