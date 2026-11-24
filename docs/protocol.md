# Clipdrop Wire Protocol Specification (v1)

## 1. Protocol Architecture & Conventions

### 1.1 Transport Protocol
- **Transport**: HTTPS over TLS 1.3 with pinned mutual X.509 certificate authentication (mTLS).
- **Default Port**: `47820` (configurable via `--port`).
- **Data Serialization**: JSON for metadata control requests; raw binary streaming for payload uploads.
- **Byte Order**: Big-endian (network byte order) for cryptographic curves; standard UTF-8 for JSON text.

### 1.2 Required Protocol Headers
All HTTP requests and responses must include the following custom header:
- `X-Protocol-Version: 1`

Requests lacking this header or presenting an unsupported version return `HTTP 400 Bad Request`.

---

## 2. API Endpoints Reference

### 2.1 Health Check & Ping (`GET /v1/ping`)
Used by the presence monitor and diagnostic runner to verify peer availability and latency.

- **Method**: `GET`
- **Path**: `/v1/ping`
- **Headers**:
  - `X-Protocol-Version: 1`
- **Request Body**: None

#### Response (`HTTP 200 OK`)
```json
{
  "status": "ok",
  "name": "macbook-air.local",
  "proto": "1",
  "time": "2026-11-24T10:00:00Z"
}
```

---

### 2.2 Pre-Flight Transfer Offer (`POST /v1/offer`)
Prior to uploading clipboard data, the sender submits an offer detailing payload size, mime-type, and SHA-256 checksum.

- **Method**: `POST`
- **Path**: `/v1/offer`
- **Headers**:
  - `X-Protocol-Version: 1`
  - `Content-Type: application/json`

#### Request Payload (`OfferRequest`)
```json
{
  "id": "1732442400000000000",
  "kind": "image",
  "size": 154238,
  "mime": "image/png",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

#### Response: Accept Transfer (`HTTP 200 OK`)
```json
{
  "action": "send"
}
```

#### Response: Skip Transfer (`HTTP 200 OK`)
Returned when the item is rejected due to policy, deduplication, or size limits.
```json
{
  "action": "skip",
  "reason": "duplicate"
}
```
**Valid Skip Reasons**:
- `duplicate`: Checksum matches the receiver's current clipboard.
- `too_large`: Size exceeds receiver's configured ceiling (`MaxImageBytes` or `MaxTextBytes`).
- `kind_disabled`: Content type disabled by receiver policy (`--images-only` or `--no-text`).

---

### 2.3 Streaming Payload Upload (`PUT /v1/items/{id}`)
Streams raw binary content for an accepted offer.

- **Method**: `PUT`
- **Path**: `/v1/items/{id}` (where `{id}` corresponds to the `id` submitted in the pre-flight offer)
- **Headers**:
  - `X-Protocol-Version: 1`
  - `X-Sha256: <lowercase 64-char hex SHA-256 digest>`
  - `Content-Type: image/png` or `text/plain; charset=utf-8`
- **Request Body**: Raw binary stream of the image or UTF-8 text bytes.

#### Response (`HTTP 200 OK`)
Empty body. Confirms data was validated, applied to OS clipboard, and scheduled for retention.

---

## 3. Ephemeral Pairing Ceremony Endpoints

During `clipdrop pair`, the host runs an ephemeral HTTP listener on a dynamically allocated port.

### 3.1 PAKE Handshake (`POST /v1/pair/pake`)
Executes the mathematical Curve P-256 point negotiation wrapping `schollz/pake/v3`.

- **Request**:
```json
{
  "point": "<base64-encoded Curve P-256 public point from joiner>"
}
```
- **Response (`HTTP 200 OK`)**:
```json
{
  "point": "<base64-encoded Curve P-256 public point from host>"
}
```

### 3.2 Credentials Swap (`POST /v1/pair/exchange`)
Exchanges identity metadata encrypted with AES-256-GCM using the 32-byte key derived from PAKE.

- **Request / Response Schema**:
```json
{
  "nonce": "<base64-encoded 12-byte GCM nonce>",
  "ciphertext": "<base64-encoded encrypted payload and 16-byte GCM tag>"
}
```
- **Decrypted Payload Model**:
```json
{
  "device_id": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
  "name": "laptop-work",
  "os": "darwin"
}
```

---

## 4. HTTP Status Code Mapping

| Status Code | Meaning | Condition |
|---|---|---|
| `200 OK` | Success | Offer processed, ping answered, or item uploaded and written. |
| `400 Bad Request` | Client Error | Missing `X-Protocol-Version`, invalid JSON, or corrupt PNG header. |
| `403 Forbidden` | TLS Handshake Drop | Remote certificate fingerprint not found in `trusted_devices.json`. |
| `409 Conflict` | Session Conflict | Ephemeral pairing host already engaged or session expired. |
| `413 Payload Too Large` | Limit Exceeded | Raw uploaded bytes exceed max permissible size. |
| `422 Unprocessable Entity` | Hash Mismatch | Checksum of received bytes does not match `X-Sha256` header. |
| `500 Internal Server Error` | System Failure | OS pasteboard write failed or filesystem error. |
