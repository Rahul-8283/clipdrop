# Clipdrop System Specification (SPEC)

## 1. System Overview

Clipdrop is an autonomous, peer-to-peer (P2P) clipboard and screenshot synchronization service designed for local network operation between macOS and Windows devices. It eliminates reliance on third-party cloud intermediaries, user accounts, and external telemetry while maintaining cryptographic confidentiality, mutual peer authentication, and low-latency data transfer.

---

## 2. Architectural Principles & Network Boundaries

### 2.1 Local-Only Subnet Operation
- Clipdrop communicates strictly across the local multicast broadcast domain (LAN / Wi-Fi).
- Traffic is never routed to public internet relays, STUN/TURN servers, or hosted cloud endpoints.
- All network operations bind to local IP interfaces and default port `47820` (configurable via `--port`).

### 2.2 Mutual Zero-Trust Model
- Untrusted local networks (such as public coffee shop Wi-Fi or conference networks) are assumed to contain hostile passive eavesdroppers and active adversaries.
- Unpaired devices or devices with mismatched cryptographic fingerprints are rejected at the TLS handshake level before any HTTP request or clipboard payload is decoded.

---

## 3. Cryptographic Identity & Transport Security

### 3.1 Device Identity Generation
- Each device generates a dedicated cryptographic identity at startup stored in `<ConfigDir>/key.pem` and `<ConfigDir>/cert.pem` (mode `0600`).
- **Key Generation**: NIST P-256 (secp256r1) Elliptic Curve Digital Signature Algorithm (ECDSA).
- **Certificate**: Self-signed X.509 certificate with a 10-year validity window, Common Name matching the device hostname, and key usage flags for digital signatures, key agreement, server authentication, and client authentication.
- **Device ID**: Canonical 64-character lowercase hexadecimal SHA-256 fingerprint calculated over the DER-encoded certificate bytes:
  $$\text{DeviceID} = \text{hex}(\text{SHA-256}(\text{Certificate}_{\text{DER}}))$$

### 3.2 Mutual TLS 1.3 Transport (mTLS)
- Transport layer security is strictly enforced at **TLS 1.3**.
- Traditional public Certificate Authorities (CAs) are bypassed (`InsecureSkipVerify: true`) in favor of direct **certificate pinning**:
  - The client and server verify peer certificates against the local `trusted_devices.json` registry.
  - Connections presenting unknown certificate digests are terminated immediately during the TLS handshake with zero application-layer error exposure.

---

## 4. Out-of-Band PAKE Pairing Ceremony

### 4.1 Security Invariants
- **No Pre-Shared Keys (PSK)**: Nodes do not share permanent secret passwords or tokens prior to pairing.
- **Short-Lived Phonetic Codes**: Human-readable codes adhering to `NNNN-word-word` (e.g., `8412-amber-falcon`) generated from high-entropy system randomness (`crypto/rand`) and a clean 256-word dictionary.
- **PAKE Negotiation**: Employs Password-Authenticated Key Exchange over NIST Curve P-256 (`schollz/pake/v3`) to derive a shared 256-bit symmetric session key over an unencrypted channel without exposing the code to eavesdroppers.
- **Brute-Force Lockout**: The host pairing listener enforces a maximum of **3 consecutive failed attempts**. Upon the third failure, the server terminates immediately and discards state.
- **Expiration Budget**: Ephemeral pairing hosts automatically expire and shut down after **120 seconds** (2 minutes).
- **Single-Use Lifecycle**: Once a pairing handshake succeeds, the ephemeral host listener shuts down immediately.

### 4.2 Credentials Exchange
- Following successful PAKE key derivation, identity payloads (certificate fingerprint, hostname, OS) are exchanged using **AES-256-GCM** authenticated encryption with random 96-bit nonces.
- Both devices append the verified peer credentials into `trusted_devices.json` with strict mode `0600`.

---

## 5. Local Discovery & Address Resolution

### 5.1 Multicast DNS (mDNS) Zeroconf
- Service Type: `_clipdrop._tcp` on domain `local.`
- Instance Name: `<first-16-fingerprint>-<hostname>`
- TXT Record Attributes:
  - `id`: Full 64-character SHA-256 certificate fingerprint.
  - `name`: Local device display name / hostname.
  - `os`: Operating system identifier (`darwin`, `windows`, `linux`).
  - `proto`: Wire protocol version (`"1"`).
  - `status`: Operational state (`"ready"` during normal operation, `"pairing"` during active pair host).

### 5.2 3-Tier Address Resolution Hierarchy
When dispatching outbound clipboard items or health checks, destination socket addresses are resolved according to strict tier priority:
1. **Tier 1 (mDNS Live Cache)**: Freshest IP and port announced via multicast DNS.
2. **Tier 2 (CLI Override)**: Address explicitly specified via `--peer ip:port`.
3. **Tier 3 (Stored Fallback)**: `last_address` persisted in `trusted_devices.json`.
- If all three tiers fail, the item is dropped safely with a log notice: `"peer offline, item dropped"`.

---

## 6. Peer Presence & Health Heartbeat

- **Interval**: A background ticker dispatches `GET /v1/ping` over mTLS every 5 seconds.
- **Edge-Triggered Logging**: State changes trigger notifications exactly once:
  - Offline to Online: `"peer is online"`
  - Online to Offline: `"peer went offline"`
  - Steady-state successes or repeated failures produce zero terminal log output.
- **Activity Tracking**: Successful pings advance `last_seen` timestamps and update `last_address` in `trusted_devices.json`.

---

## 7. Engine Pipeline & Echo Suppression

### 7.1 Outbound Transfer Pipeline
1. Local pasteboard monitor detects native clipboard modification.
2. Content is classified as `text` (UTF-8, max 1MB) or `image` (valid PNG headers, max 25MB).
3. Payload digest $\text{SHA-256}(\text{data})$ is computed.
4. **Self-Echo Suppression**: If the digest matches `LastReceivedHash`, the event is dropped (preventing ping-pong loops).
5. **Deduplication Check**: If the digest matches `LastSentHash`, the duplicate copy is dropped.
6. The client issues `POST /v1/offer` to all online trusted peers.
7. If the peer responds with `action: "send"`, the payload is streamed via `PUT /v1/items/{id}` with header `X-Sha256`.

### 7.2 Inbound Transfer Pipeline
1. The mTLS server validates peer credentials and verifies protocol headers (`X-Protocol-Version: 1`).
2. Payload bytes are streamed, checksummed on the fly, and validated against PNG headers.
3. Server records payload digest into `LastReceivedHash` in the local sync engine.
4. Payload is written directly to the host OS pasteboard.
5. Inbound content is saved asynchronously to `<ConfigDir>/received/`.

---

## 8. Received Items Archiving & Retention Policy

- **Directory**: `<ConfigDir>/received/` created with restricted permissions (`0700`).
- **Naming Pattern**: `YYYYMMDDTHHMMSSZ_<sha256[:8]>.<png|txt>` (sanitized against directory traversal).
- **Pruning Ceiling**: Background cleaner enforces an upper bound of **20 files**. When items exceed 20, the oldest files are permanently deleted.

---

## 9. Concurrency & Goroutine Architecture

The unified sync runtime coordinates up to 6 background routines under a root cancellation context:
1. **Platform Clipboard Watcher**: Monitors system pasteboard.
2. **Discovery Announcer**: Publishes mDNS `_clipdrop._tcp` records.
3. **Discovery Browser**: Ingests subnet advertisements and maintains the routing table.
4. **Transport Server**: Listens for incoming mTLS offers and uploads.
5. **Presence Monitor**: Dispatches 5-second health pings.
6. **Optional Screenshot Watcher**: Monitors the macOS screenshot directory when `--watch-screenshots` is enabled.

**Graceful Teardown**: Upon receiving `SIGINT` or `SIGTERM`, all routines terminate within a **3-second shutdown budget**.

---

## 10. Deliberate Non-Goals

- **No WAN / Cloud Relays**: Strictly local subnet P2P; no STUN/TURN, WebRTC, or Tailscale tunnels.
- **No Infinite History Database**: Retains strictly the 20 most recent received items.
- **No Privilege Escalation**: Diagnostics and sync run under normal unprivileged user accounts.
