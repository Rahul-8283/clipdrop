# Clipdrop Troubleshooting & Operational Runbook

This guide covers common network, firewall, and permission issues encountered when synchronizing clipboard contents across macOS and Windows.

---

## 1. Quick Health Check: `clipdrop doctor`

Whenever synchronization fails or peers appear offline, start by running the diagnostic tool:

```bash
clipdrop doctor
```

The doctor command evaluates:
- Configuration directory permissions and disk writability.
- Validity and expiration of device cryptographic keys (`key.pem` and `cert.pem`).
- Integrity of `trusted_devices.json`.
- Availability of the configured TCP synchronization port.
- Multicast DNS network interface status.
- Live mTLS ping reachability to all trusted peers.
- Operating system firewall rules and pasteboard security permissions.

---

## 2. Wi-Fi Access Point Client Isolation

### Symptoms
- `clipdrop pair join` fails to discover the pairing host.
- `clipdrop doctor` reports `WARN` on Peer Connectivity (`0/1 peers reachable`).
- Both laptops are connected to the same Wi-Fi, but cannot communicate.

### Root Cause
Many enterprise, hotel, university, and public guest Wi-Fi networks enable **Client Isolation** (also called AP Isolation). This router setting blocks direct peer-to-peer communication between wireless devices on the same subnet, preventing both multicast discovery (mDNS) and direct TCP connections.

### Remediation Steps
1. **Verify Isolation via Ping**:
   Obtain the IP address of the peer device and test basic reachability:
   ```bash
   ping <peer-ip>
   ```
   If packets drop 100%, client isolation is active on the access point.

2. **Use a Mobile Hotspot**:
   Connect both laptops to a personal phone Wi-Fi hotspot or dedicated travel router. Hotspots do not enforce client isolation.

3. **Direct CLI Address Override**:
   If multicast mDNS packets are filtered but unicast TCP traffic is allowed, override discovery manually:
   ```bash
   clipdrop run --peer <peer-ip>:47820
   ```

---

## 3. Windows Defender Firewall & Network Profiles

### Symptoms
- macOS reports `"peer offline, item dropped"`.
- Windows never receives incoming items.
- Windows `clipdrop doctor` flags `Windows Firewall` or `Windows Network Profile`.

### Remediation Steps

#### Step 1: Switch Network Profile from 'Public' to 'Private'
Windows restricts inbound local traffic on networks marked as **Public**.
1. Open **Windows Settings** > **Network & Internet** > **Wi-Fi**.
2. Click your active Wi-Fi connection.
3. Change **Network profile type** from **Public** to **Private**.

Alternatively, run PowerShell as Administrator:
```powershell
Set-NetConnectionProfile -Name "YourWiFiName" -NetworkCategory Private
```

#### Step 2: Add an Inbound Firewall Rule for Clipdrop
Run PowerShell as Administrator to allow inbound TCP traffic for Clipdrop:
```powershell
New-NetFirewallRule -DisplayName "Clipdrop" -Direction Inbound -Program "$((Get-Process -Id $PID).Path)" -Action Allow -Profile Private
```

Or open port `47820` specifically:
```powershell
New-NetFirewallRule -DisplayName "Clipdrop Port 47820" -Direction Inbound -LocalPort 47820 -Protocol TCP -Action Allow -Profile Private
```

---

## 4. macOS Pasteboard & Terminal Security Permissions

### Symptoms
- `clipdrop doctor` flags `macOS Pasteboard Permissions` with `FAIL`.
- Copied items on other machines do not paste into macOS applications.

### Remediation Steps
1. Open **System Settings** > **Privacy & Security** > **App Management** (or **Accessibility**).
2. Ensure your terminal emulator (**Terminal**, **iTerm2**, or **Ghostty**) is granted permissions.
3. If macOS prompts *"Terminal would like to access data from other apps"*, select **Allow**.

---

## 5. macOS Screenshot Folder Access

### Symptoms
- `clipdrop run --watch-screenshots` does not sync screenshots taken with `Cmd+Shift+4`.
- `clipdrop doctor` reports `WARN` on `macOS Screencapture Location`.

### Remediation Steps
1. Check configured screenshot directory:
   ```bash
   defaults read com.apple.screencapture location
   ```
2. If unset, screenshots default to `~/Desktop`. Ensure the directory exists:
   ```bash
   mkdir -p ~/Desktop
   ```
3. Reset screenshot destination to default if needed:
   ```bash
   defaults delete com.apple.screencapture location
   killall SystemUIServer
   ```

---

## 6. Validating Multicast DNS (mDNS) Flow

To check whether mDNS advertisements are broadcasting correctly on your subnet:

### On macOS:
Browse for active Clipdrop instances using the native `dns-sd` utility:
```bash
dns-sd -B _clipdrop._tcp local.
```
You should observe entries appearing with instance names like `<fingerprint16>-<hostname>`.

### On Windows:
Inspect active listening ports to ensure Clipdrop is bound:
```powershell
netstat -ano | findstr 47820
```

---

## 7. Resetting Credentials & Pairings

If device identities or trust records become corrupted:
```bash
# macOS
rm -rf "$HOME/Library/Application Support/clipdrop"

# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:APPDATA\clipdrop"
```
Rerun `clipdrop run` to generate a fresh identity, followed by `clipdrop pair` to establish a new mutual pairing.
