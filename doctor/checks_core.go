package doctor

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/discovery"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/store"
)

// CoreChecks returns an ordered slice of all standard platform-agnostic diagnostic checks.
func CoreChecks() []Check {
	return []Check{
		&ConfigDirCheck{},
		&IdentityCheck{},
		&TrustedStoreCheck{},
		&PortAvailabilityCheck{},
		&MulticastDNSCheck{},
		&PeerConnectivityCheck{},
	}
}

// AllChecks returns all diagnostic checks, combining standard core checks with OS-specific checks.
func AllChecks() []Check {
	all := CoreChecks()
	platform := PlatformChecks()
	if len(platform) > 0 {
		all = append(all, platform...)
	}
	return all
}

// ConfigDirCheck validates that the configuration directory exists, is writable,
// and enforces strict permissions (0700 on Unix).
type ConfigDirCheck struct{}

func (c *ConfigDirCheck) Name() string {
	return "Config Directory"
}

func (c *ConfigDirCheck) Run(_ context.Context, cfg *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	dir := cfg.ConfigDir
	if dir == "" {
		resolved, err := config.Dir()
		if err != nil {
			res.Status = StatusFail
			res.Summary = fmt.Sprintf("Failed to resolve config directory: %v", err)
			res.Remediation = "Ensure user home directory environment variable is set."
			return res
		}
		dir = resolved
	}

	info, err := os.Stat(dir)
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Directory %s does not exist: %v", dir, err)
		res.Remediation = fmt.Sprintf("Run: mkdir -p %s && chmod 700 %s", dir, dir)
		return res
	}

	if !info.IsDir() {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("%s exists but is not a directory", dir)
		res.Remediation = fmt.Sprintf("Remove conflicting file %s and recreate directory.", dir)
		return res
	}

	// Verify permissions on Unix
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0700 {
			res.Status = StatusFail
			res.Summary = fmt.Sprintf("Insecure permissions on %s: mode is %04o, want 0700", dir, perm)
			res.Remediation = fmt.Sprintf("Run: chmod 700 %s", dir)
			return res
		}
	}

	// Test disk writability
	tmpFile, err := os.CreateTemp(dir, ".doctor-write-test-*")
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Directory %s is not writable: %v", dir, err)
		res.Remediation = fmt.Sprintf("Run: chmod 700 %s or verify disk write permissions.", dir)
		return res
	}
	tmpName := tmpFile.Name()
	_ = tmpFile.Close()
	_ = os.Remove(tmpName)

	res.Status = StatusPass
	res.Summary = fmt.Sprintf("Path exists, writable, mode %04o", info.Mode().Perm())
	return res
}

// IdentityCheck verifies that key.pem and cert.pem exist, form a valid NIST P-256
// ECDSA keypair and X.509 certificate, and are unexpired.
type IdentityCheck struct{}

func (c *IdentityCheck) Name() string {
	return "Device Identity"
}

func (c *IdentityCheck) Run(_ context.Context, cfg *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	dir := cfg.ConfigDir
	if dir == "" {
		dir, _ = config.Dir()
	}

	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("key.pem missing or unreadable: %v", err)
		res.Remediation = "Run 'clipdrop run' to regenerate a fresh device identity."
		return res
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("cert.pem missing or unreadable: %v", err)
		res.Remediation = "Run 'clipdrop run' to regenerate a fresh device identity."
		return res
	}

	tlsCert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Corrupt credentials: %v", err)
		res.Remediation = "Run 'clipdrop run' to regenerate a fresh device identity."
		return res
	}

	if len(tlsCert.Certificate) == 0 {
		res.Status = StatusFail
		res.Summary = "No certificates found in cert.pem"
		res.Remediation = "Run 'clipdrop run' to regenerate a fresh device identity."
		return res
	}

	parsedCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Failed to parse X.509 certificate: %v", err)
		res.Remediation = "Run 'clipdrop run' to regenerate a fresh device identity."
		return res
	}

	// Verify expiration
	now := time.Now()
	if now.After(parsedCert.NotAfter) {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Certificate expired on %s", parsedCert.NotAfter.Format("2006-01-02"))
		res.Remediation = "Run 'clipdrop run' to regenerate a fresh device identity."
		return res
	}
	if now.Before(parsedCert.NotBefore) {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Certificate not yet valid (valid from %s)", parsedCert.NotBefore.Format("2006-01-02"))
		res.Remediation = "Verify system clock settings or run 'clipdrop run' to regenerate credentials."
		return res
	}

	// Verify NIST P-256 ECDSA key
	privKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || privKey.Curve.Params().Name != "P-256" {
		res.Status = StatusFail
		res.Summary = "Private key is not a NIST P-256 ECDSA key"
		res.Remediation = "Run 'clipdrop run' to regenerate a fresh device identity."
		return res
	}

	res.Status = StatusPass
	res.Summary = fmt.Sprintf("Valid NIST P-256 keypair, certificate unexpired (valid until %s)", parsedCert.NotAfter.Format("2006-01-02"))
	return res
}

// TrustedStoreCheck verifies that trusted_devices.json exists or can be created,
// and parses as valid JSON adhering to the device schema.
type TrustedStoreCheck struct{}

func (c *TrustedStoreCheck) Name() string {
	return "Trusted Store"
}

func (c *TrustedStoreCheck) Run(_ context.Context, cfg *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	dir := cfg.ConfigDir
	if dir == "" {
		dir, _ = config.Dir()
	}

	storePath := filepath.Join(dir, "trusted_devices.json")
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		res.Status = StatusPass
		res.Summary = "trusted_devices.json does not exist yet (will be created on first pair)"
		return res
	}

	st, err := store.New(storePath)
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Failed to parse trusted_devices.json: %v", err)
		res.Remediation = "Inspect file for JSON corruption or delete to reset pairings."
		return res
	}

	devices := st.List()
	res.Status = StatusPass
	res.Summary = fmt.Sprintf("trusted_devices.json is valid JSON with %d registered device(s)", len(devices))
	return res
}

// PortAvailabilityCheck tests whether the configured synchronization port can be bound to TCP.
type PortAvailabilityCheck struct{}

func (c *PortAvailabilityCheck) Name() string {
	return "Port Availability"
}

func (c *PortAvailabilityCheck) Run(_ context.Context, cfg *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	port := cfg.Port
	if port <= 0 {
		port = 47820
	}

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Port %d cannot be bound: %v", port, err)
		res.Remediation = "Port is in use by another process. Specify an alternate with --port."
		return res
	}
	_ = ln.Close()

	res.Status = StatusPass
	res.Summary = fmt.Sprintf("Port %d is available for binding", port)
	return res
}

// MulticastDNSCheck verifies that local network interfaces support multicast and
// can bind to the mDNS address group 224.0.0.251:5353.
type MulticastDNSCheck struct{}

func (c *MulticastDNSCheck) Name() string {
	return "Multicast DNS"
}

func (c *MulticastDNSCheck) Run(_ context.Context, _ *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	ifaces, err := net.Interfaces()
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Failed to list network interfaces: %v", err)
		res.Remediation = "Verify network adapter status and permissions."
		return res
	}

	hasMulticast := false
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagMulticast != 0 {
			hasMulticast = true
			break
		}
	}

	if !hasMulticast {
		res.Status = StatusFail
		res.Summary = "No active network interface with multicast support found"
		res.Remediation = "Local network interface does not support multicast. Use --peer ip:port."
		return res
	}

	addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("Failed to resolve mDNS multicast address: %v", err)
		res.Remediation = "Local network interface does not support multicast. Use --peer ip:port."
		return res
	}

	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		// On some platforms/sandboxes binding 5353 directly may be restricted or already held,
		// but if multicast interfaces exist, report as WARN with remediation guidance
		res.Status = StatusWarn
		res.Summary = fmt.Sprintf("Multicast interface enabled, but socket bind to 224.0.0.251:5353 returned: %v", err)
		res.Remediation = "Local network interface does not support multicast. Use --peer ip:port."
		return res
	}
	_ = conn.Close()

	res.Status = StatusPass
	res.Summary = "Multicast interface is enabled and can bind to 224.0.0.251:5353"
	return res
}

// PeerConnectivityCheck iterates through all registered trusted devices,
// sending a 3-second mTLS ping to assess connectivity.
type PeerConnectivityCheck struct {
	client *transport.Client
}

// WithClient sets a custom transport.Client (e.g., for testing with in-memory pipes).
func (c *PeerConnectivityCheck) WithClient(client *transport.Client) *PeerConnectivityCheck {
	c.client = client
	return c
}

func (c *PeerConnectivityCheck) Name() string {
	return "Peer Connectivity"
}

func (c *PeerConnectivityCheck) Run(ctx context.Context, cfg *config.Config) *Result {
	start := time.Now()
	res := &Result{Name: c.Name()}
	defer func() { res.Latency = time.Since(start) }()

	dir := cfg.ConfigDir
	if dir == "" {
		dir, _ = config.Dir()
	}

	storePath := filepath.Join(dir, "trusted_devices.json")
	st, err := store.New(storePath)
	if err != nil {
		res.Status = StatusWarn
		res.Summary = fmt.Sprintf("Could not load trusted store: %v", err)
		res.Remediation = "Inspect file for JSON corruption or delete to reset pairings."
		return res
	}

	devices := st.List()
	if len(devices) == 0 {
		res.Status = StatusPass
		res.Summary = "No trusted peers configured (run 'clipdrop pair' to pair with a device)"
		return res
	}

	client := c.client
	if client == nil {
		ident, err := identity.LoadOrGenerate(dir, cfg.DeviceName)
		if err != nil {
			res.Status = StatusWarn
			res.Summary = fmt.Sprintf("Cannot load identity for peer authentication: %v", err)
			res.Remediation = "Run 'clipdrop run' to regenerate a fresh device identity."
			return res
		}
		client = transport.NewClient(ident, st)
	}

	resolver := discovery.NewResolver(cfg, st)

	reachableCount := 0
	for _, dev := range devices {
		addr, err := resolver.Resolve(dev.ID)
		if err != nil || addr == "" {
			continue
		}

		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, pErr := client.Ping(pingCtx, addr)
		cancel()

		if pErr == nil {
			reachableCount++
		}
	}

	if reachableCount == 0 {
		res.Status = StatusWarn
		res.Summary = fmt.Sprintf("0/%d trusted peers responded to ping", len(devices))
		res.Remediation = "Peer is offline, on a different Wi-Fi, or blocked by client isolation."
		return res
	}

	res.Status = StatusPass
	res.Summary = fmt.Sprintf("%d/%d trusted peer(s) reachable via mTLS ping", reachableCount, len(devices))
	return res
}
