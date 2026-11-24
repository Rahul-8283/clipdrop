package test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/app"
	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/doctor"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

func TestDoctor_ConfigDirCheck_SuccessAndFailure(t *testing.T) {
	check := &doctor.ConfigDirCheck{}

	// 1. Valid directory with mode 0700
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0700)
	cfg := config.Defaults()
	cfg.ConfigDir = tempDir

	res := check.Run(context.Background(), &cfg)
	if res.Status != doctor.StatusPass {
		t.Fatalf("expected StatusPass for valid config dir, got %s: %s", res.Status, res.Summary)
	}

	// 2. Non-existent directory
	nonExistentCfg := config.Defaults()
	nonExistentCfg.ConfigDir = filepath.Join(tempDir, "does-not-exist")
	resFail := check.Run(context.Background(), &nonExistentCfg)
	if resFail.Status != doctor.StatusFail {
		t.Fatalf("expected StatusFail for non-existent dir, got %s", resFail.Status)
	}
	if resFail.Remediation == "" {
		t.Fatal("expected remediation advice on failure")
	}

	// 3. Wide permissions on Unix
	if runtime.GOOS != "windows" {
		insecureDir := t.TempDir()
		if err := os.Chmod(insecureDir, 0777); err == nil {
			insecureCfg := config.Defaults()
			insecureCfg.ConfigDir = insecureDir
			resInsecure := check.Run(context.Background(), &insecureCfg)
			if resInsecure.Status != doctor.StatusFail {
				t.Fatalf("expected StatusFail for insecure permissions, got %s", resInsecure.Status)
			}
		}
	}
}

func TestDoctor_IdentityCheck_SuccessAndFailure(t *testing.T) {
	check := &doctor.IdentityCheck{}

	// 1. Valid Identity
	tempDir := t.TempDir()
	_, err := identity.LoadOrGenerate(tempDir, "doctor-node")
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	cfg := config.Defaults()
	cfg.ConfigDir = tempDir

	res := check.Run(context.Background(), &cfg)
	if res.Status != doctor.StatusPass {
		t.Fatalf("expected StatusPass for valid identity, got %s: %s", res.Status, res.Summary)
	}

	// 2. Missing key.pem
	missingDir := t.TempDir()
	missingCfg := config.Defaults()
	missingCfg.ConfigDir = missingDir
	resMissing := check.Run(context.Background(), &missingCfg)
	if resMissing.Status != doctor.StatusFail {
		t.Fatalf("expected StatusFail for missing identity, got %s", resMissing.Status)
	}

	// 3. Corrupted cert.pem
	corruptDir := t.TempDir()
	_, _ = identity.LoadOrGenerate(corruptDir, "corrupt-node")
	_ = os.WriteFile(filepath.Join(corruptDir, "cert.pem"), []byte("invalid cert pem data"), 0600)
	corruptCfg := config.Defaults()
	corruptCfg.ConfigDir = corruptDir

	resCorrupt := check.Run(context.Background(), &corruptCfg)
	if resCorrupt.Status != doctor.StatusFail {
		t.Fatalf("expected StatusFail for corrupt cert, got %s", resCorrupt.Status)
	}

	// 4. Expired certificate
	expiredDir := t.TempDir()
	createExpiredIdentity(t, expiredDir)
	expiredCfg := config.Defaults()
	expiredCfg.ConfigDir = expiredDir

	resExpired := check.Run(context.Background(), &expiredCfg)
	if resExpired.Status != doctor.StatusFail {
		t.Fatalf("expected StatusFail for expired certificate, got %s", resExpired.Status)
	}
}

func createExpiredIdentity(t *testing.T, dir string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "expired-node"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // Expired yesterday
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating expired cert: %v", err)
	}

	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	_ = os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0600)
	_ = os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0600)
}

func TestDoctor_TrustedStoreCheck_SuccessAndFailure(t *testing.T) {
	check := &doctor.TrustedStoreCheck{}

	// 1. Missing store -> PASS (created on first pair)
	tempDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tempDir

	resEmpty := check.Run(context.Background(), &cfg)
	if resEmpty.Status != doctor.StatusPass {
		t.Fatalf("expected StatusPass for empty store, got %s: %s", resEmpty.Status, resEmpty.Summary)
	}

	// 2. Populated store -> PASS
	storePath := filepath.Join(tempDir, "trusted_devices.json")
	st, err := store.New(storePath)
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	_ = st.Add(&store.Device{
		ID:          "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
		Name:        "remote-laptop",
		OS:          "windows",
		LastAddress: "192.168.1.100:47820",
	})

	resPopulated := check.Run(context.Background(), &cfg)
	if resPopulated.Status != doctor.StatusPass {
		t.Fatalf("expected StatusPass for populated store, got %s: %s", resPopulated.Status, resPopulated.Summary)
	}

	// 3. Corrupt store -> FAIL
	_ = os.WriteFile(storePath, []byte("{invalid-json-schema"), 0600)
	resCorrupt := check.Run(context.Background(), &cfg)
	if resCorrupt.Status != doctor.StatusFail {
		t.Fatalf("expected StatusFail for corrupt store JSON, got %s", resCorrupt.Status)
	}
	if resCorrupt.Remediation == "" {
		t.Fatal("expected remediation advice for corrupt store")
	}
}

func TestDoctor_PortAvailabilityCheck(t *testing.T) {
	check := &doctor.PortAvailabilityCheck{}

	// 1. Free dynamic port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind test listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // Close so port is immediately free

	cfg := config.Defaults()
	cfg.Port = port

	res := check.Run(context.Background(), &cfg)
	if res.Status != doctor.StatusPass {
		t.Fatalf("expected StatusPass for free port %d, got %s: %s", port, res.Status, res.Summary)
	}

	// 2. Occupied port -> FAIL
	busyLn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Skipf("cannot bind port %d for conflict test: %v", port, err)
	}
	defer busyLn.Close()

	resOccupied := check.Run(context.Background(), &cfg)
	if resOccupied.Status != doctor.StatusFail {
		t.Fatalf("expected StatusFail for occupied port %d, got %s: %s", port, resOccupied.Status, resOccupied.Summary)
	}
	if resOccupied.Remediation == "" {
		t.Fatal("expected remediation for occupied port")
	}
}

func TestDoctor_MulticastDNSCheck(t *testing.T) {
	check := &doctor.MulticastDNSCheck{}
	cfg := config.Defaults()

	res := check.Run(context.Background(), &cfg)
	// In some environments, it may return PASS or WARN depending on network permissions, but not fail arbitrarily
	if res.Status == doctor.StatusFail && res.Remediation == "" {
		t.Fatal("expected remediation for multicast failure")
	}
}

func TestDoctor_PeerConnectivityCheck(t *testing.T) {
	check := &doctor.PeerConnectivityCheck{}

	// 1. No peers in store -> PASS
	tempDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tempDir

	resNoPeers := check.Run(context.Background(), &cfg)
	if resNoPeers.Status != doctor.StatusPass {
		t.Fatalf("expected StatusPass when no peers configured, got %s: %s", resNoPeers.Status, resNoPeers.Summary)
	}

	// 2. Peer configured but unreachable -> WARN
	st, _ := store.New(filepath.Join(tempDir, "trusted_devices.json"))
	_ = st.Add(&store.Device{
		ID:          "aabbccddeeff11223344556677889900aabbccddeeff11223344556677889900",
		Name:        "unreachable-device",
		OS:          "windows",
		LastAddress: "192.0.2.1:47820", // TEST-NET-1 (unroutable)
	})

	resUnreachable := check.Run(context.Background(), &cfg)
	if resUnreachable.Status != doctor.StatusWarn {
		t.Fatalf("expected StatusWarn when peers unreachable, got %s: %s", resUnreachable.Status, resUnreachable.Summary)
	}
	if resUnreachable.Remediation == "" {
		t.Fatal("expected remediation for unreachable peer")
	}

	// 3. Peer configured and reachable -> PASS
	peerDir := t.TempDir()
	peerIdent, _ := identity.LoadOrGenerate(peerDir, "peer-node")
	peerStore, _ := store.New(filepath.Join(peerDir, "trusted_devices.json"))
	localIdent, _ := identity.LoadOrGenerate(tempDir, cfg.DeviceName)

	_ = peerStore.Add(&store.Device{
		ID:   localIdent.DeviceID,
		Name: cfg.DeviceName,
		OS:   "darwin",
	})

	// Server on peer side
	peerCfg := config.Defaults()
	peerCfg.ConfigDir = peerDir
	peerClip := clipboard.NewFake()
	peerEng := engine.New(&peerCfg, peerClip)

	rawListener := newMemPipeListener("reachable-peer.local:47820")
	peerTLS := transport.ServerTLSConfig(peerIdent, peerStore)
	tlsListener := tls.NewListener(rawListener, peerTLS)

	peerServer, _ := transport.NewServerWithListener(&peerCfg, peerIdent, peerStore, peerEng, tlsListener)
	go func() { _ = peerServer.Start() }()
	defer func() { _ = peerServer.Close() }()

	clientTLS := transport.ClientTLSConfig(localIdent, st)
	tr := &http.Transport{
		TLSClientConfig: clientTLS,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			select {
			case <-rawListener.closed:
				return nil, net.ErrClosed
			case rawListener.conns <- serverConn:
				return clientConn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		DisableKeepAlives: true,
	}
	memClient := transport.NewClientWithHTTPClient(&http.Client{Transport: tr})

	// Update local store with peer address and fingerprint
	_ = st.Add(&store.Device{
		ID:          peerIdent.DeviceID,
		Name:        "reachable-peer",
		OS:          "darwin",
		LastAddress: "reachable-peer.local:47820",
	})

	checkWithClient := (&doctor.PeerConnectivityCheck{}).WithClient(memClient)
	resReachable := checkWithClient.Run(context.Background(), &cfg)
	if resReachable.Status != doctor.StatusPass {
		t.Fatalf("expected StatusPass when peer reachable, got %s: %s", resReachable.Status, resReachable.Summary)
	}
}

func TestDoctor_AllChecks_And_PlatformChecks(t *testing.T) {
	all := doctor.AllChecks()
	if len(all) < 6 {
		t.Fatalf("expected at least 6 core checks, got %d", len(all))
	}

	platform := doctor.PlatformChecks()
	if runtime.GOOS == "darwin" {
		if len(platform) != 2 {
			t.Fatalf("expected 2 macOS platform checks, got %d", len(platform))
		}
		for _, check := range platform {
			res := check.Run(context.Background(), nil)
			if res.Status == doctor.StatusFail && res.Remediation == "" {
				t.Fatalf("check %s failed without remediation advice", check.Name())
			}
		}
	}
}

type mockCheck struct {
	name        string
	status      doctor.Status
	summary     string
	remediation string
}

func (m *mockCheck) Name() string { return m.name }
func (m *mockCheck) Run(_ context.Context, _ *config.Config) *doctor.Result {
	return &doctor.Result{
		Name:        m.name,
		Status:      m.status,
		Latency:     5 * time.Millisecond,
		Summary:     m.summary,
		Remediation: m.remediation,
	}
}

func TestDoctor_Runner_StatusAggregation(t *testing.T) {
	// 1. All Pass -> Overall Pass
	rPass := doctor.NewRunner(
		&mockCheck{name: "Check 1", status: doctor.StatusPass, summary: "ok"},
		&mockCheck{name: "Check 2", status: doctor.StatusPass, summary: "ok"},
	)
	repPass := rPass.RunAll(context.Background(), nil)
	if repPass.Overall != doctor.StatusPass {
		t.Fatalf("expected StatusPass, got %s", repPass.Overall)
	}

	// 2. Contains Warn, no Fail -> Overall Warn
	rWarn := doctor.NewRunner(
		&mockCheck{name: "Check 1", status: doctor.StatusPass, summary: "ok"},
		&mockCheck{name: "Check 2", status: doctor.StatusWarn, summary: "warning"},
	)
	repWarn := rWarn.RunAll(context.Background(), nil)
	if repWarn.Overall != doctor.StatusWarn {
		t.Fatalf("expected StatusWarn, got %s", repWarn.Overall)
	}

	// 3. Contains Fail -> Overall Fail
	rFail := doctor.NewRunner(
		&mockCheck{name: "Check 1", status: doctor.StatusPass, summary: "ok"},
		&mockCheck{name: "Check 2", status: doctor.StatusWarn, summary: "warning"},
		&mockCheck{name: "Check 3", status: doctor.StatusFail, summary: "broken"},
	)
	repFail := rFail.RunAll(context.Background(), nil)
	if repFail.Overall != doctor.StatusFail {
		t.Fatalf("expected StatusFail, got %s", repFail.Overall)
	}
}

func TestDoctor_Printer_OutputFormatting(t *testing.T) {
	rep := &doctor.Report{
		Results: []*doctor.Result{
			{Name: "Core Filesystem", Status: doctor.StatusPass, Latency: 2 * time.Millisecond, Summary: "Path exists"},
			{Name: "Firewall Rule", Status: doctor.StatusWarn, Latency: 5 * time.Millisecond, Summary: "Rule disabled", Remediation: "Enable rule in firewall"},
			{Name: "Identity Cert", Status: doctor.StatusFail, Latency: 10 * time.Millisecond, Summary: "Certificate expired", Remediation: "Run clipdrop run to regenerate"},
		},
		Overall:      doctor.StatusFail,
		TotalLatency: 17 * time.Millisecond,
	}

	cfg := config.Defaults()
	cfg.ConfigDir = "/tmp/test-config-dir"

	var buf bytes.Buffer
	if err := doctor.PrintReport(&buf, rep, &cfg); err != nil {
		t.Fatalf("PrintReport failed: %v", err)
	}
	out := buf.String()

	// Assert headers
	if !strings.Contains(out, "Clipdrop Diagnostics (doctor)") {
		t.Fatal("missing header title")
	}
	if !strings.Contains(out, "CHECK") || !strings.Contains(out, "STATUS") || !strings.Contains(out, "SUMMARY") {
		t.Fatal("missing table column headers")
	}

	// Assert check rows
	if !strings.Contains(out, "Core Filesystem") || !strings.Contains(out, "Path exists") {
		t.Fatal("missing check 1 in output")
	}
	if !strings.Contains(out, "Firewall Rule") || !strings.Contains(out, "Identity Cert") {
		t.Fatal("missing check rows in output")
	}

	// Assert remediation section
	if !strings.Contains(out, "Remediation Advice:") {
		t.Fatal("missing remediation advice header")
	}
	if !strings.Contains(out, "Enable rule in firewall") || !strings.Contains(out, "Run clipdrop run to regenerate") {
		t.Fatal("missing remediation hints in output")
	}

	// Assert banner
	if !strings.Contains(out, "Overall: ISSUES DETECTED") {
		t.Fatalf("expected 'Overall: ISSUES DETECTED' banner, got: %s", out)
	}
}

func TestDoctor_RunDoctor_CommandIntegration(t *testing.T) {
	tempDir := t.TempDir()
	_ = config.EnsureDir(tempDir)
	_, _ = identity.LoadOrGenerate(tempDir, "doctor-test")

	cfg := config.Defaults()
	cfg.ConfigDir = tempDir

	var buf bytes.Buffer
	err := app.RunDoctorWithOutput(context.Background(), &cfg, &buf)
	// Because on clean config dir, either all pass or only peer connectivity warns
	if err != nil && !errors.Is(err, doctor.ErrChecksFailed) {
		t.Fatalf("unexpected error from RunDoctorWithOutput: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Clipdrop Diagnostics (doctor)") {
		t.Fatalf("expected doctor header in output, got: %s", out)
	}
}
