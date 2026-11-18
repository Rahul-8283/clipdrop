# Clipdrop 

> **Zero-cloud, end-to-end encrypted, peer-to-peer clipboard and screenshot synchronization between macOS and Windows over local Wi-Fi.**

---

### Tech Stack & Core Libraries

<p align="left">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/macOS-Darwin-000000?style=for-the-badge&logo=apple&logoColor=white" alt="macOS" />
  <img src="https://img.shields.io/badge/Windows-11%20%2F%2010-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/Security-mTLS%201.3%20%2B%20ECDSA-green?style=for-the-badge&logo=shield" alt="mTLS 1.3" />
  <img src="https://img.shields.io/badge/Pairing-PAKE%20(schollz/pake)-orange?style=for-the-badge&logo=auth0&logoColor=white" alt="PAKE" />
  <img src="https://img.shields.io/badge/Discovery-mDNS%20Zeroconf-blue?style=for-the-badge&logo=airplayvideo" alt="mDNS Zeroconf" />
  <img src="https://img.shields.io/badge/Logging-log%2Fslog-lightgrey?style=for-the-badge&logo=codeforces" alt="slog" />
</p>

---

## 🌟 Highlights

- **🔒 Zero Cloud & Zero Telemetry:** Direct P2P transfer over local subnet; no accounts, no relays, no third parties.
- **🛡️ Mutual TLS 1.3 & Pinned Fingerprints:** Custom CA-less trust model. Unpaired peers are dropped at the TLS handshake.
- **🤝 PAKE Out-of-Band Pairing:** 2-minute time-limited pairing code using Password-Authenticated Key Exchange with AES-GCM credential exchange.
- **🔄 Smart Echo Loop Prevention:** Content hashing (SHA-256) and receiver origin tracking guarantee zero ping-pong copy loops.
- **📸 Screenshot-First Design:** Instant PNG validation, size checks, and sub-2-second sync across platforms.

---

## 🏛️ System Architecture

```mermaid
flowchart TB
    subgraph macOS["macOS (Darwin)"]
        subgraph MacPlatform["Platform Layer"]
            MacClip["Clipboard Watcher (cgo / Cocoa)"]
            MacStore["Config & Key Store (~/Library/.../clipdrop)"]
        end
        subgraph MacEngine["Core Engine"]
            MacDedupe["Dedupe & Echo Filter"]
            MacPolicy["Size / MIME / PNG Validator"]
        end
        subgraph MacNet["Networking & Discovery"]
            MacDiscovery["mDNS Browse & Announce"]
            MacServer["mTLS 1.3 Server (:47820)"]
            MacClient["mTLS 1.3 Client"]
        end
    end

    subgraph LocalNetwork["Local Wi-Fi Network"]
        MDNS["mDNS Multicast (_clipdrop._tcp)"]
        MTLS["Mutual TLS 1.3 Encrypted Channel"]
    end

    subgraph Windows["Windows (x86_64)"]
        subgraph WinNet["Networking & Discovery"]
            WinDiscovery["mDNS Browse & Announce"]
            WinServer["mTLS 1.3 Server (:47820)"]
            WinClient["mTLS 1.3 Client"]
        end
        subgraph WinEngine["Core Engine"]
            WinDedupe["Dedupe & Echo Filter"]
            WinPolicy["Size / MIME / PNG Validator"]
        end
        subgraph WinPlatform["Platform Layer"]
            WinClip["Clipboard Watcher (Win32 API)"]
            WinStore["Config & Key Store (%AppData%/clipdrop)"]
        end
    end

    MacClip --> MacDedupe
    MacDedupe --> MacPolicy
    MacPolicy --> MacClient
    MacClient --> MTLS
    MTLS --> WinServer
    WinServer --> WinPolicy
    WinPolicy --> WinDedupe
    WinDedupe --> WinClip

    WinClip --> WinDedupe
    WinDedupe --> WinPolicy
    WinPolicy --> WinClient
    WinClient --> MTLS
    MTLS --> MacServer
    MacServer --> MacPolicy
    MacPolicy --> MacDedupe
    MacDedupe --> MacClip

    MacDiscovery <--> MDNS
    WinDiscovery <--> MDNS
```

---

## 🤝 Pairing Protocol (PAKE + Credential Exchange)

Before normal synchronization begins, devices establish trust using a temporary pairing listener and Password-Authenticated Key Exchange (PAKE).

```mermaid
sequenceDiagram
    autonumber
    actor HostUser as Host (e.g. Mac)
    participant Host as Host Engine
    participant TempServer as Temp Pairing Listener
    participant Joiner as Joiner Engine
    actor JoinUser as Joiner (e.g. Windows)

    HostUser->>Host: clipdrop pair
    Host->>TempServer: Spawn ephemeral listener (2-min expiry)
    Host->>Host: Generate code (e.g. 4821-hawk-moon)
    Host-->>HostUser: Display pairing code
    Host->>Host: Broadcast mDNS "_clipdrop._tcp" (status=pairing)

    JoinUser->>Joiner: clipdrop pair join
    JoinUser->>Joiner: Enter code: 4821-hawk-moon
    Joiner->>Joiner: Discover Host via mDNS / --addr
    Joiner->>TempServer: Initiate PAKE handshake (over TLS)

    Note over Host,Joiner: schollz/pake v3 Key Exchange
    Joiner<<->>TempServer: Exchange PAKE Points (derived from pairing code)
    Host->>Host: Compute shared session key
    Joiner->>Joiner: Compute shared session key

    Note over Host,Joiner: Identity Exchange (AES-GCM encrypted via session key)
    Joiner->>TempServer: Encrypted payload (Cert Fingerprint, Name, OS)
    TempServer->>Joiner: Encrypted payload (Cert Fingerprint, Name, OS)

    Host->>Host: Save Joiner to trusted_devices.json (0600)
    Joiner->>Joiner: Save Host to trusted_devices.json (0600)
    Host->>TempServer: Shutdown ephemeral listener
    Host-->>HostUser: "Paired with Windows-Laptop"
    Joiner-->>JoinUser: "Paired with MacBook-Pro"
```

---

## ⚡ Sync Protocol & Echo Prevention

The sync engine follows an **Offer / Upload** sequence with strict hash recording to prevent infinite feedback loops.

```mermaid
sequenceDiagram
    autonumber
    participant SourceClip as Device A: Clipboard
    participant EngineA as Device A: Engine
    participant TransportA as Device A: Client
    participant TransportB as Device B: Server
    participant EngineB as Device B: Engine
    participant DestClip as Device B: Clipboard

    SourceClip->>EngineA: Clipboard change event
    EngineA->>EngineA: Read data & compute SHA-256 (HashX)
    EngineA->>EngineA: Check: HashX == LastReceivedHash? (Prevent Echo)

    EngineA->>TransportA: Transmit Offer
    TransportA->>TransportB: POST /v1/offer {id, kind, size, sha256, mime}

    EngineB->>EngineB: Check duplicate: HashX == CurrentLocalHash?
    alt Duplicate or Too Large
        TransportB-->>TransportA: 200 OK {"action": "skip", "reason": "duplicate"}
    else Ready to receive
        TransportB-->>TransportA: 200 OK {"action": "send"}
        TransportA->>TransportB: PUT /v1/items/{id} (Raw Bytes, Header: X-Sha256)
        TransportB->>EngineB: Verify payload size & SHA-256
        EngineB->>EngineB: Validate PNG header/dimensions (for images)
        EngineB->>EngineB: Record HashX as LastReceivedHash
        EngineB->>DestClip: Write content to OS Clipboard
        EngineB->>EngineB: Archive in ~/received/ (keep newest 20)
        TransportB-->>TransportA: 200 OK {"status": "applied"}
    end
```

---

## 🔄 Engine State & Decision Machine

```mermaid
stateDiagram-v2
    [*] --> Idle

    Idle --> Detecting: Clipboard Event
    Detecting --> Inspecting: Read Content (Text / Image)
    
    Inspecting --> Suppressed: Hash equals LastReceivedHash (Echo)
    Inspecting --> Suppressed: Size exceeds limit (Image > 25MB, Text > 1MB)
    Inspecting --> Suppressed: Flag restricted (--images-only / --no-text)
    Suppressed --> Idle: Discard

    Inspecting --> ResolvingPeers: Valid New Content
    ResolvingPeers --> Idle: No peers online (Drop)
    
    ResolvingPeers --> Offering: Peer Found (mDNS / LastAddress)
    Offering --> Idle: Peer returned "skip"
    Offering --> Uploading: Peer returned "send"
    
    Uploading --> Idle: Transfer Complete & Confirmed
```

---

## 🔐 Security & Identity Architecture

```mermaid
flowchart LR
    subgraph Gen["Identity Initialization (First Run)"]
        GenKey["crypto/ecdsa: P-256 Keypair"]
        GenCert["crypto/x509: Self-Signed Cert"]
        GenFP["SHA-256 Cert Fingerprint = Device ID"]
        FileStore[("Config Dir (0600)\n- key.pem\n- cert.pem\n- trusted_devices.json")]

        GenKey --> GenCert --> GenFP --> FileStore
    end

    subgraph Handshake["mTLS 1.3 Connection Handshake"]
        ClientHello["Peer connects"]
        CertVerify{"Is Peer Cert Fingerprint\nin trusted_devices.json?"}
        Allow["Allow Handshake & Sync"]
        Drop["Reject & Terminate Connection"]

        ClientHello --> CertVerify
        CertVerify -- Yes --> Allow
        CertVerify -- No --> Drop
    end
```

---

## 🗂️ Project Structure

```mermaid
flowchart TD
    Root["clipdrop/"]
    Cmd["cmd/clipdrop/ (Entry Point & CLI Dispatch)"]
    Internal["internal/"]

    App["app/ (Component wiring & lifecycle)"]
    Config["config/ (Paths, defaults, env)"]
    Identity["identity/ (ECDSA keys, certs, fingerprint)"]
    Platform["platform/clipboard/ (darwin, windows, fake)"]
    Engine["engine/ (Event loops, dedupe, echo filter)"]
    Netx["netx/"]
    NetxDisc["discovery/ (mDNS zeroconf)"]
    NetxPair["pairing/ (PAKE listener & exchange)"]
    NetxTrans["transport/ (mTLS HTTP server & client)"]
    Store["store/ (trusted_devices.json, received/ retention)"]
    Doctor["doctor/ (Health, firewall, and permission diagnostics)"]

    Root --> Cmd
    Root --> Internal
    Internal --> App
    Internal --> Config
    Internal --> Identity
    Internal --> Platform
    Internal --> Engine
    Internal --> Netx
    Netx --> NetxDisc
    Netx --> NetxPair
    Netx --> NetxTrans
    Internal --> Store
    Internal --> Doctor
```

---

## 💻 CLI Commands & Usage

| Command | Description |
|---|---|
| `clipdrop pair` | **Host side:** Generate a single-use pairing code and open temporary pairing listener (2-min limit). |
| `clipdrop pair join` | **Joiner side:** Input pairing code, discover host over mDNS, and complete PAKE trust exchange. |
| `clipdrop run` | Start the sync daemon in the foreground. Clean exit with `Ctrl+C`. |
| `clipdrop devices` | List all paired and trusted devices with fingerprint and last-seen timestamps. |
| `clipdrop unpair <name>` | Revoke trust for a device and invalidate future mTLS connections. |
| `clipdrop doctor` | Run diagnostics: port availability, permissions, identity files, mDNS multicast, peer pings. |
| `clipdrop version` | Print current build version and protocol specification. |

### Common Flags for `clipdrop run`
- `--images-only` : Disable text clipboard synchronization.
- `--no-text` : Synonym for image-exclusive synchronization.
- `--port <number>` : Custom mTLS listening port (default: `47820`).
- `--peer <ip:port>` : Manual fallback address if mDNS multicast is blocked on the network.
- `--verbose` : Enable detailed `log/slog` debug tracing.

---

## 📄 License

This project is licensed under the [MIT License](file:///Users/rahulls/Projects/Screenshot_Sync/Clipdrop/LICENSE).
