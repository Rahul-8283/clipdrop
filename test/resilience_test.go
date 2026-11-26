package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/app"
	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/discovery"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

func TestResilience_WiFiDisconnectAndIPRoaming(t *testing.T) {
	nodeA := createSyncNode(t, "roam-mac", 47880)

	// Setup Node B identity/store/clipboard shared across IP roam
	dirB := t.TempDir()
	identB, err := identity.LoadOrGenerate(dirB, "roam-win")
	if err != nil {
		t.Fatalf("identB: %v", err)
	}
	stB, _ := store.New(filepath.Join(dirB, "trusted_devices.json"))
	clipB := clipboard.NewFake()
	cfgB := config.Defaults()
	cfgB.ConfigDir = dirB
	cfgB.DeviceName = "roam-win"
	engB := engine.New(&cfgB, clipB)

	_ = nodeA.store.Add(&store.Device{
		ID:   identB.DeviceID,
		Name: "roam-win",
		OS:   "windows",
	})
	_ = stB.Add(&store.Device{
		ID:   nodeA.ident.DeviceID,
		Name: nodeA.name,
		OS:   "darwin",
	})

	const addr1 = "192.168.1.50:47881"
	const addr2 = "192.168.1.99:47882"

	rawLn1 := newMemPipeListener(addr1)
	rawLn2 := newMemPipeListener(addr2)

	var routeMu sync.RWMutex
	routes := map[string]*memPipeListener{
		addr1: rawLn1,
	}

	tr := &http.Transport{
		TLSClientConfig: transport.ClientTLSConfig(nodeA.ident, nodeA.store),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			routeMu.RLock()
			ln := routes[addr]
			routeMu.RUnlock()
			if ln == nil {
				return nil, net.ErrClosed
			}
			clientConn, serverConn := net.Pipe()
			select {
			case <-ln.closed:
				return nil, net.ErrClosed
			case ln.conns <- serverConn:
				return clientConn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 2 * time.Second,
	}
	dynamicClient := transport.NewClientWithHTTPClient(&http.Client{Transport: tr})
	nodeA.pipeline.SetClient(dynamicClient)

	// Start Node B server #1 at addr1
	srvB1, err := transport.NewServerWithListener(&cfgB, identB, stB, engB, tls.NewListener(rawLn1, transport.ServerTLSConfig(identB, stB)))
	if err != nil {
		t.Fatalf("srvB1: %v", err)
	}
	_ = srvB1.Start()

	// Capture slog output to verify edge-triggered online/offline transitions
	var logBuf safeBuffer
	origLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(origLogger)

	pm := app.NewPresenceMonitorWithPinger(nodeA.cfg, nodeA.store, dynamicClient, nodeA.pipeline.Resolver())
	pm.SetInterval(30 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = nodeA.pipeline.Run(ctx) }()
	go func() { _ = pm.Start(ctx) }()

	// Announce addr1
	nodeA.pipeline.Resolver().UpdateFromMDNS(identB.DeviceID, "roam-win", discovery.StatusReady, addr1)

	// 1. Wait for online transition
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !pm.IsOnline(identB.DeviceID) {
		time.Sleep(15 * time.Millisecond)
	}
	if !pm.IsOnline(identB.DeviceID) {
		t.Fatalf("expected peer to come online at %s", addr1)
	}

	// 2. Simulate Wi-Fi disconnect on Node B
	_ = srvB1.Close()
	routeMu.Lock()
	delete(routes, addr1)
	routeMu.Unlock()

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && pm.IsOnline(identB.DeviceID) {
		time.Sleep(15 * time.Millisecond)
	}
	if pm.IsOnline(identB.DeviceID) {
		t.Fatal("expected PresenceMonitor to mark peer offline after disconnect")
	}

	// 3. Simulate IP roaming: Node B comes back on addr2
	srvB2, err := transport.NewServerWithListener(&cfgB, identB, stB, engB, tls.NewListener(rawLn2, transport.ServerTLSConfig(identB, stB)))
	if err != nil {
		t.Fatalf("srvB2: %v", err)
	}
	_ = srvB2.Start()
	defer func() { _ = srvB2.Close() }()

	routeMu.Lock()
	routes[addr2] = rawLn2
	routeMu.Unlock()
	nodeA.pipeline.Resolver().UpdateFromMDNS(identB.DeviceID, "roam-win", discovery.StatusReady, addr2)

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !pm.IsOnline(identB.DeviceID) {
		time.Sleep(15 * time.Millisecond)
	}
	if !pm.IsOnline(identB.DeviceID) {
		t.Fatalf("expected PresenceMonitor to mark peer online at new roamed addr %s", addr2)
	}

	// Verify edge-triggered log transitions (2 online, 1 offline)
	logs := logBuf.String()
	if got := strings.Count(logs, "peer is online"); got != 2 {
		t.Fatalf("expected 2 'peer is online' logs (initial + roamed), got %d; logs:\n%s", got, logs)
	}
	if got := strings.Count(logs, "peer went offline"); got != 1 {
		t.Fatalf("expected 1 'peer went offline' log, got %d; logs:\n%s", got, logs)
	}

	// 4. Verify subsequent clipboard item syncs immediately without restarting Node A
	roamMsg := "synced-after-ip-roam"
	if err := nodeA.fakeClip.Write(&clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte(roamMsg),
		Mime: "text/plain; charset=utf-8",
	}); err != nil {
		t.Fatalf("nodeA write failed: %v", err)
	}

	var received *clipboard.Item
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if item, err := clipB.Read(); err == nil && item != nil && string(item.Data) == roamMsg {
			received = item
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if received == nil {
		t.Fatal("Node B did not receive synced item after IP roaming")
	}
}

type abruptEOFConn struct {
	net.Conn
	written   atomic.Int64
	cutoff    int64
	closedErr atomic.Bool
}

func (c *abruptEOFConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.written.Add(int64(n)) >= c.cutoff && c.closedErr.CompareAndSwap(false, true) {
		_ = c.Conn.Close()
		return n, net.ErrClosed
	}
	return n, err
}

func TestResilience_MidTransferAbruptEOF(t *testing.T) {
	dirA := t.TempDir()
	identA, _ := identity.LoadOrGenerate(dirA, "eof-server")
	stA, _ := store.New(filepath.Join(dirA, "trusted_devices.json"))

	dirB := t.TempDir()
	identB, _ := identity.LoadOrGenerate(dirB, "eof-client")
	stB, _ := store.New(filepath.Join(dirB, "trusted_devices.json"))

	_ = stA.Add(&store.Device{ID: identB.DeviceID, Name: "eof-client", OS: "windows"})
	_ = stB.Add(&store.Device{ID: identA.DeviceID, Name: "eof-server", OS: "darwin"})

	cfgA := config.Defaults()
	cfgA.ConfigDir = dirA
	cfgA.DeviceName = "eof-server"
	clipA := clipboard.NewFake()
	engA := engine.New(&cfgA, clipA)

	rawLn := newMemPipeListener("eof-server.local:47883")
	srvA, err := transport.NewServerWithListener(&cfgA, identA, stA, engA, tls.NewListener(rawLn, transport.ServerTLSConfig(identA, stA)))
	if err != nil {
		t.Fatalf("NewServerWithListener: %v", err)
	}
	_ = srvA.Start()
	defer func() { _ = srvA.Close() }()

	// Client that abruptly drops TCP/pipe mid-body
	abruptTr := &http.Transport{
		TLSClientConfig: transport.ClientTLSConfig(identB, stB),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			select {
			case <-rawLn.closed:
				return nil, net.ErrClosed
			case rawLn.conns <- serverConn:
				return &abruptEOFConn{
					Conn:   clientConn,
					cutoff: 256 * 1024, // Drop abruptly after 256KB
				}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		DisableKeepAlives: true,
	}
	abruptClient := transport.NewClientWithHTTPClient(&http.Client{Transport: abruptTr})

	largePayload := bytes.Repeat([]byte("Z"), 2*1024*1024)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := abruptClient.Upload(ctx, "eof-server.local:47883", "abrupt-1", largePayload, clipboard.KindText, "text/plain; charset=utf-8", engine.ComputeHash(largePayload)); err == nil {
		t.Fatal("expected abrupt mid-body EOF upload to return error")
	}

	// Verify 0 bytes polluted receiver clipboard
	if item, _ := clipA.Read(); item != nil {
		t.Fatalf("expected clipboard to remain empty after abrupt EOF, got %d bytes", len(item.Data))
	}

	// Verify server continues serving subsequent valid requests cleanly
	_, healthyClient := newSecurityMTLSClient(identB, stB, rawLn)
	validMsg := []byte("healthy-after-eof")
	if err := healthyClient.Upload(ctx, "eof-server.local:47883", "recovery-1", validMsg, clipboard.KindText, "text/plain; charset=utf-8", engine.ComputeHash(validMsg)); err != nil {
		t.Fatalf("expected server to serve subsequent valid upload cleanly, got: %v", err)
	}

	got, err := clipA.Read()
	if err != nil || got == nil || !bytes.Equal(got.Data, validMsg) {
		t.Fatalf("expected valid recovery message on clipboard, got: %v (err=%v)", got, err)
	}

	// Allow background retention archival goroutine to finish before TempDir cleanup.
	time.Sleep(50 * time.Millisecond)
}

func TestResilience_RapidRepeatedCopies(t *testing.T) {
	nodeA := createSyncNode(t, "rapid-mac", 47884)
	nodeB := createSyncNode(t, "rapid-win", 47885)

	_ = nodeA.store.Add(&store.Device{ID: nodeB.ident.DeviceID, Name: nodeB.name, OS: "windows", LastAddress: "rapid-win.local:47885"})
	_ = nodeB.store.Add(&store.Device{ID: nodeA.ident.DeviceID, Name: nodeA.name, OS: "darwin", LastAddress: "rapid-mac.local:47884"})

	nodeA.pipeline.SetClient(connectSyncClient(nodeA, nodeB))
	nodeA.pipeline.Resolver().UpdateFromMDNS(nodeB.ident.DeviceID, nodeB.name, discovery.StatusReady, "rapid-win.local:47885")
	nodeB.pipeline.SetClient(connectSyncClient(nodeB, nodeA))
	nodeB.pipeline.Resolver().UpdateFromMDNS(nodeA.ident.DeviceID, nodeA.name, discovery.StatusReady, "rapid-mac.local:47884")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = nodeA.pipeline.Run(ctx) }()
	go func() { _ = nodeB.pipeline.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Rapidly copy 3 distinct snippets within <100ms
	snippets := []string{"rapid-snippet-1", "rapid-snippet-2", "rapid-snippet-3-final"}
	for _, s := range snippets {
		_ = nodeA.fakeClip.Write(&clipboard.Item{
			Kind: clipboard.KindText,
			Data: []byte(s),
			Mime: "text/plain; charset=utf-8",
		})
		time.Sleep(20 * time.Millisecond)
	}

	// Verify Node B stabilizes on the final snippet without deadlocking
	deadline := time.Now().Add(2 * time.Second)
	stabilized := false
	for time.Now().Before(deadline) {
		if item, err := nodeB.fakeClip.Read(); err == nil && item != nil && string(item.Data) == "rapid-snippet-3-final" {
			stabilized = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !stabilized {
		got, _ := nodeB.fakeClip.Read()
		t.Fatalf("Node B failed to stabilize on final rapid snippet; got=%v", got)
	}
}

func TestResilience_ImageOnlyPolicyEnforcement(t *testing.T) {
	dirA := t.TempDir()
	identA, _ := identity.LoadOrGenerate(dirA, "imgonly-node-a")
	stA, _ := store.New(filepath.Join(dirA, "trusted_devices.json"))

	dirB := t.TempDir()
	identB, _ := identity.LoadOrGenerate(dirB, "imgonly-node-b")
	stB, _ := store.New(filepath.Join(dirB, "trusted_devices.json"))

	_ = stA.Add(&store.Device{ID: identB.DeviceID, Name: "imgonly-node-b", OS: "windows"})
	_ = stB.Add(&store.Device{ID: identA.DeviceID, Name: "imgonly-node-a", OS: "darwin"})

	cfgA := config.Defaults()
	cfgA.ConfigDir = dirA
	cfgA.DeviceName = "imgonly-node-a"
	cfgA.ImagesOnly = true // Enforce --images-only
	clipA := clipboard.NewFake()
	engA := engine.New(&cfgA, clipA)

	rawLn := newMemPipeListener("imgonly-a.local:47886")
	srvA, err := transport.NewServerWithListener(&cfgA, identA, stA, engA, tls.NewListener(rawLn, transport.ServerTLSConfig(identA, stA)))
	if err != nil {
		t.Fatalf("NewServerWithListener: %v", err)
	}
	_ = srvA.Start()
	defer func() { _ = srvA.Close() }()

	_, clientB := newSecurityMTLSClient(identB, stB, rawLn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Text offer must be skipped with reason="kind_disabled"
	txtData := fmt.Appendf(nil, "text blocked by policy %d", time.Now().UnixNano())
	txtResp, err := clientB.Offer(ctx, "imgonly-a.local:47886", &transport.OfferRequest{
		ID:     "txt-offer-1",
		Kind:   string(clipboard.KindText),
		Size:   int64(len(txtData)),
		Mime:   "text/plain; charset=utf-8",
		Sha256: engine.ComputeHash(txtData),
	})
	if err != nil {
		t.Fatalf("text offer failed: %v", err)
	}
	if txtResp.Action != transport.ActionSkip || txtResp.Reason != transport.ReasonKindDisabled {
		t.Fatalf("expected skip/kind_disabled, got action=%q reason=%q", txtResp.Action, txtResp.Reason)
	}

	if item, _ := clipA.Read(); item != nil {
		t.Fatalf("expected Node A clipboard to remain untouched, got %+v", item)
	}

	// 2. Image offer must still be accepted
	pngData := makeMockPNG(6, 6)
	imgResp, err := clientB.Offer(ctx, "imgonly-a.local:47886", &transport.OfferRequest{
		ID:     "img-offer-1",
		Kind:   string(clipboard.KindImage),
		Size:   int64(len(pngData)),
		Mime:   "image/png",
		Sha256: engine.ComputeHash(pngData),
	})
	if err != nil {
		t.Fatalf("image offer failed: %v", err)
	}
	if imgResp.Action != transport.ActionSend {
		t.Fatalf("expected image offer action=send, got %q (reason=%q)", imgResp.Action, imgResp.Reason)
	}
}
