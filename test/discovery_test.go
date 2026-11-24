package test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/discovery"
	"github.com/Rahul-8283/clipdrop/store"
	"github.com/grandcat/zeroconf"
)

func TestRecord_InstanceNameAndTXT(t *testing.T) {
	deviceID := "A1B2C3D4E5F67890123456789012345678901234567890123456789012345678"
	hostname := "rahuls-macbook"

	instance := discovery.BuildInstanceName(deviceID, hostname)
	expectedInstance := "a1b2c3d4e5f67890-rahuls-macbook"
	if instance != expectedInstance {
		t.Fatalf("BuildInstanceName() = %q; want %q", instance, expectedInstance)
	}

	// Empty hostname fallback
	fallbackInstance := discovery.BuildInstanceName(deviceID, "")
	if fallbackInstance != "a1b2c3d4e5f67890-node" {
		t.Fatalf("BuildInstanceName() with empty host = %q; want %q", fallbackInstance, "a1b2c3d4e5f67890-node")
	}

	// TXT serialization and deserialization
	rec := discovery.Record{
		ID:     deviceID,
		Name:   hostname,
		OS:     "darwin",
		Proto:  "1",
		Status: discovery.StatusReady,
	}

	txt := discovery.BuildTXT(rec)
	parsed := discovery.ParseTXT(txt)

	lowerID := "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
	if parsed.ID != lowerID {
		t.Errorf("parsed.ID = %q; want %q", parsed.ID, lowerID)
	}
	if parsed.Name != hostname || parsed.OS != "darwin" || parsed.Proto != "1" || parsed.Status != discovery.StatusReady {
		t.Errorf("parsed record mismatch: %+v", parsed)
	}
}

func TestResolver_ThreeTierHierarchy(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	peerID := "a1b2c3d4e5f678901234567890123456"

	// 1. Initial state: No address available -> ErrPeerOffline
	cfg := config.Defaults()
	resolver := discovery.NewResolver(&cfg, st)

	_, err = resolver.Resolve(peerID)
	if !errors.Is(err, discovery.ErrPeerOffline) {
		t.Fatalf("expected ErrPeerOffline when no tier available, got %v", err)
	}

	// 2. Add Tier 3: Stored LastAddress
	_ = st.Add(&store.Device{
		ID:          peerID,
		Name:        "remote-peer",
		OS:          "windows",
		LastAddress: "192.168.1.50:47820",
	})

	addr, err := resolver.Resolve(peerID)
	if err != nil {
		t.Fatalf("Tier 3 resolution failed: %v", err)
	}
	if addr != "192.168.1.50:47820" {
		t.Fatalf("expected Tier 3 address '192.168.1.50:47820', got %q", addr)
	}

	// 3. Add Tier 2: CLI --peer override -> takes precedence over Tier 3
	cfg.PeerAddr = "10.0.0.99:47820"
	addr, err = resolver.Resolve(peerID)
	if err != nil {
		t.Fatalf("Tier 2 resolution failed: %v", err)
	}
	if addr != "10.0.0.99:47820" {
		t.Fatalf("expected Tier 2 override '10.0.0.99:47820', got %q", addr)
	}

	// 4. Add Tier 1: Active mDNS discovered address -> takes precedence over both Tier 2 and Tier 3
	resolver.UpdateFromMDNS(peerID, "remote-peer", discovery.StatusReady, "172.16.0.5:47820")
	addr, err = resolver.Resolve(peerID)
	if err != nil {
		t.Fatalf("Tier 1 resolution failed: %v", err)
	}
	if addr != "172.16.0.5:47820" {
		t.Fatalf("expected Tier 1 active mDNS address '172.16.0.5:47820', got %q", addr)
	}

	// Verify Get and OnlinePeers
	peerInfo, ok := resolver.Get(peerID)
	if !ok || peerInfo.Address != "172.16.0.5:47820" {
		t.Fatalf("Get returned invalid peer: %+v", peerInfo)
	}

	peers := resolver.OnlinePeers()
	if len(peers) != 1 || peers[0].DeviceID != peerID {
		t.Fatalf("OnlinePeers returned invalid list: %+v", peers)
	}

	// Remove mDNS -> falls back to Tier 2
	resolver.RemoveMDNS(peerID)
	addr, err = resolver.Resolve(peerID)
	if err != nil {
		t.Fatalf("fallback resolution failed: %v", err)
	}
	if addr != "10.0.0.99:47820" {
		t.Fatalf("expected fallback to Tier 2 '10.0.0.99:47820', got %q", addr)
	}
}

func TestBrowser_HandleEntry(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	cfg := config.Defaults()
	resolver := discovery.NewResolver(&cfg, st)
	browser := discovery.NewBrowser(resolver)

	peerID := "aabbccddeeff00112233445566778899"
	txt := discovery.BuildTXT(discovery.Record{
		ID:     peerID,
		Name:   "linux-box",
		OS:     "linux",
		Proto:  "1",
		Status: discovery.StatusReady,
	})

	entry := &zeroconf.ServiceEntry{
		HostName: "linux-box.local.",
		Port:     47820,
		Text:     txt,
		AddrIPv4: []net.IP{net.ParseIP("192.168.1.150")},
	}

	browser.HandleEntry(entry)

	addr, err := resolver.Resolve(peerID)
	if err != nil {
		t.Fatalf("failed to resolve peer after browser handle entry: %v", err)
	}
	if addr != "192.168.1.150:47820" {
		t.Fatalf("expected resolved address '192.168.1.150:47820', got %q", addr)
	}

	peer, ok := resolver.Get(peerID)
	if !ok || peer.Name != "linux-box" || peer.Status != discovery.StatusReady {
		t.Fatalf("unexpected peer metadata in resolver: %+v", peer)
	}
}

func TestAnnouncer_Lifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	ident, err := identity.LoadOrGenerate(tmpDir, "test-announcer")
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	announcer, err := discovery.Announce(ctx, ident, 47825, discovery.StatusReady)
	if err != nil {
		t.Skipf("skipping mDNS network binding in restricted sandbox environment: %v", err)
		return
	}
	defer announcer.Shutdown()

	if announcer.Status() != discovery.StatusReady {
		t.Errorf("initial status = %q; want %q", announcer.Status(), discovery.StatusReady)
	}

	// Allow initial mDNS probe goroutine in grandcat/zeroconf to settle before updating TXT
	time.Sleep(300 * time.Millisecond)

	if err := announcer.SetStatus(discovery.StatusPairing); err != nil {
		t.Fatalf("SetStatus failed: %v", err)
	}

	if announcer.Status() != discovery.StatusPairing {
		t.Errorf("updated status = %q; want %q", announcer.Status(), discovery.StatusPairing)
	}
}
