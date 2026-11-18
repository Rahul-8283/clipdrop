# Clipdrop v1 — Build Spec

## 0. How to work
- Build milestone by milestone (section 10). Finish and test one before starting the next.
- Before using any library, check its current docs and confirm the API still matches. Do not guess function names.
- Only use the dependencies listed in section 3. Ask before adding others.
- Keep ALL OS-specific code inside platform behind interfaces, using Go build tags.
- Keep the core logic testable with a fake clipboard and fake peers. No test may need a real clipboard or real network except the marked integration tests.
- Respect the non-goals in section 11. Do not build tray, autostart, cloud, or Tailscale code.

## 1. What we're building
A single Go program, run manually in a terminal on two laptops (a MacBook and a Windows laptop) on the same Wi-Fi. Once paired, anything copied on one laptop (image or text) can be pasted on the other, in both directions. Screenshots are the main use case: a screenshot copied to the clipboard on Windows must paste on the Mac, and vice versa.
Privacy rules: no cloud, no accounts, no telemetry. Traffic is encrypted and only paired devices are accepted.

## 2. Commands
- clipdrop pair — host side: generates a short single-use pairing code (format like 4821-hawk-moon), prints it, waits up to 2 minutes for the other laptop.
- clipdrop pair join — joiner side: prompts for the code, finds the host (mDNS, or --addr ip:port as fallback), completes pairing.
- clipdrop run — start syncing in the foreground. Ctrl+C stops cleanly.
- clipdrop devices — list paired devices.
- clipdrop unpair <name> — remove trust for a device.
- clipdrop doctor — diagnose problems (section 8).
- clipdrop version
Flags for run: --images-only, --no-text, --port (default 47820), --peer ip:port (manual peer address fallback), --verbose.
Use the standard flag package with subcommands. Do not add cobra.

## 3. Tech stack
- Go 1.22+. Module path: github.com/<username>/clipdrop.
- Clipboard (text + images): golang.design/x/clipboard, wrapped in our own interface. Use its watch feature for change detection. Images are handled as PNG bytes.
- Discovery: mDNS via github.com/grandcat/zeroconf (service type _clipdrop._tcp). If this library has problems, propose an alternative before switching.
- Pairing: PAKE via github.com/schollz/pake (v3).
- Transport: standard library net/http over TLS 1.3 with mutual authentication and pinned certificates (crypto/tls, crypto/x509, crypto/ecdsa). No custom crypto.
- Storage: JSON files in the user config directory (os.UserConfigDir()/clipdrop), file permissions 0600. No SQLite in v1.
- Logging: log/slog.
- Testing: go test with the race detector.
- Build natively on each OS. macOS needs Xcode command line tools because the clipboard library uses cgo there. Windows needs no C toolchain.

## 4. Folder structure
```
clipdrop/
├── cmd/
│   └── clipdrop/
│       └── main.go                  # entry point, subcommand dispatch
│
├── app/                             # wires components together, startup and shutdown
├── config/                          # config dir, settings, defaults
├── identity/                        # device keypair, self-signed cert, fingerprint
│
├── platform/
│   ├── clipboard/
│   │   ├── clipboard.go             # interface
│   │   ├── clipboard_real.go        # wraps golang.design/x/clipboard
│   │   └── clipboard_fake.go        # in-memory fake for tests
│   └── screenshots/                 # optional (M8): Mac screenshot-folder watcher
│
├── imaging/                         # PNG validation, size and dimension checks
├── engine/                          # event handling, dedupe, echo prevention, policy
│
├── netx/
│   ├── discovery/                   # mDNS announce and browse
│   ├── pairing/                     # PAKE flow, temporary pairing listener
│   └── transport/                   # mTLS server and client, offer/upload protocol
│
├── store/                           # trusted-devices JSON file, received-items folder
├── doctor/                          # diagnostic checks
│
├── docs/
│   ├── SPEC.md
│   ├── protocol.md
│   └── troubleshooting.md
│
├── testdata/
├── .gitignore
├── go.mod
├── go.sum
├── LICENSE
├── Makefile
└── README.md
```

## 5. Device identity and trust
- First run generates an ECDSA P-256 key and a self-signed certificate. Store both in the config dir (0600). Device ID = SHA-256 fingerprint of the certificate. Device name = hostname, editable in config.
- Trusted devices file holds: device ID (fingerprint), name, OS, paired_at, last_seen, last_address.
- The TLS config requires a client certificate and verifies that the peer's certificate fingerprint is in the trusted list. Unknown fingerprints are rejected during the handshake and logged.
- Revoking a device = deleting it from the trusted list (unpair).

## 6. Pairing flow
1. Host runs pair. It starts a TEMPORARY listener (separate from the main server) and announces itself via mDNS as "pairing". It prints the code and expires it after 2 minutes. The code is single-use and allows at most 3 failed attempts.
2. Joiner runs pair join, enters the code, discovers the host (or uses --addr), and connects.
3. Both sides run the PAKE exchange using the code. If it fails, abort with a clear message.
4. Using the PAKE-derived session key, each side sends its certificate fingerprint, device name, and OS, encrypted and authenticated with that key (AES-GCM).
5. Each side saves the other to its trusted devices file. Both print "Paired with <name>".
6. The temporary listener shuts down.
Pairing never happens on the main server, which only accepts already-trusted devices.

## 7. Sync protocol (docs/protocol.md must document this)
Both laptops run the server and act as a client. Server listens on the configured port (default 47820) with mTLS. Every request carries header X-Proto-Version: 1; mismatches get a clear error.

Endpoints:
- GET /v1/ping → 200 with device name and protocol version. Used for peer health.
- POST /v1/offer — JSON body: id (uuid), kind ("image" or "text"), size (bytes), sha256, mime. Reply JSON: action ("send" or "skip") and reason. Skip reasons: duplicate, too_large, paused, kind_disabled. Duplicate = the offered hash equals the hash of the content currently on the receiver's clipboard.
- PUT /v1/items/{id} — raw bytes. Header X-Sha256 must match. Receiver verifies size and hash, validates PNG for images, then applies to clipboard. Reply: 200 applied, 413 too large, 422 hash mismatch, 400 invalid content.

Limits: images 25 MB, text 1 MB (configurable). Timeouts: connect 3 s, offer 3 s, upload 15 s.

## 8. Engine behavior
Send path:
1. Clipboard watcher fires with new content.
2. Normalize (PNG for images, UTF-8 for text). Compute SHA-256. Check flags and size limits.
3. If the hash equals the hash of the last item we applied FROM a peer, ignore it (this prevents echo loops).
4. Resolve each trusted peer's address (mDNS cache, else --peer, else last_address). If none is reachable, log "peer offline, item dropped". No queue in v1.
5. Offer, then upload if the peer says send.
Receive path:
1. Server gets the upload and verifies it.
2. Record the hash as "last applied from peer" BEFORE writing the clipboard.
3. Write to the clipboard. Save a copy in the received folder (keep the newest 20, delete older).
4. Log "Received image, 1.2 MB from <name>".
Peer presence: ping each trusted peer every 5 seconds and log online/offline transitions only.
Concurrency: one goroutine each for clipboard watcher, mDNS announce, mDNS browse, server, and presence checker, all stopped through one cancellation context.

doctor checks: config dir writable; identity exists; trusted devices present; server port free and bindable; mDNS announce and browse works; each trusted peer reachable (ping); on Windows, print instructions for allowing the app and its port through the firewall on Private networks; on macOS, print notes on clipboard and notification permission prompts. Output a pass/fail list with a fix hint per failure.

## 9. Edge cases to handle
- Peer asleep, offline, or on a different network: log clearly, never crash.
- Wi-Fi change or laptop wake: re-announce mDNS and refresh peer addresses.
- mDNS blocked (guest Wi-Fi, client isolation): fall back to --peer or last_address, and doctor explains it.
- Windows Public network profile or firewall blocking inbound: doctor detects unreachable peer and prints guidance.
- Oversized or non-PNG image: reject with a reason, never write to the clipboard.
- Clipboard read errors or empty clipboard: log at debug, continue.
- Rapid repeated copies: process only the latest if one is still uploading.
- Same screenshot copied twice: handled by the duplicate rule in the offer step.
- Unknown device connects: reject at handshake, log with fingerprint.
- Pairing code wrong, expired, or reused: clear error, host keeps waiting until expiry or the attempt limit.
- Ctrl+C mid-transfer: cancel cleanly, no partial clipboard write.
- Text can contain copied passwords: warn on first run, and provide --no-text and --images-only. (Password-manager flag detection is a v2 item.)

## 10. Milestones (each has an acceptance test)
M1 Skeleton: repo, go.mod, subcommand dispatch, config dir, slog logging, version command. Test: commands run on both OSes.
M2 Clipboard layer: interface, real implementations, fake. Run prints a line for every clipboard change (kind, size, hash). Test: a Win+Shift+S screenshot on Windows and Cmd+Ctrl+Shift+4 on Mac are detected as images.
M3 Identity: key and certificate generation, fingerprint, stored with 0600 permissions. Unit tests.
M4 Transport: mTLS server and client, ping, offer, upload, hash checks. Integration test with two in-process instances on localhost. Include a test that an unknown certificate is rejected.
M5 Dedupe and echo prevention in the engine, with unit tests using the fake clipboard (A copies, B applies, B does not send it back).
M6 Pairing: PAKE flow, temporary listener, code expiry and attempt limits, trusted devices file, devices and unpair commands. Test across two real machines.
M7 Discovery and full loop: mDNS announce and browse, presence pings, full sync both directions. Test: Windows screenshot pastes on Mac, Mac screenshot pastes on Windows, text both ways, no echo loop.
M8 (optional) Mac screenshot-file watcher: watch the system screenshot folder (read the location from macOS settings, do not assume Desktop), wait until file size is stable, then treat it like a clipboard image. Behind a --watch-screenshots flag.
M9 Doctor, README, docs/protocol.md, docs/troubleshooting.md, cleanup of received folder, and a manual test checklist.

## 11. Non-goals for v1
No tray or menu bar, no autostart, no background service or control API, no offline queue, no history UI, no SQLite, no file transfer, no Tailscale or internet relay, no more than two devices tested, no password-manager detection.

## 12. Definition of done
- On a fresh Mac and fresh Windows laptop on the same Wi-Fi: build, pair once, run, copy a screenshot on one, paste on the other in under about 2 seconds, in both directions.
- Text copy and paste works both ways.
- No echo loops or duplicate pastes during 10 minutes of normal use.
- An unpaired third device cannot connect.
- go test -race passes. README explains setup in under 10 steps.