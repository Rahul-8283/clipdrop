package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/app"
	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/discovery"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

type syncNode struct {
	name     string
	cfg      *config.Config
	ident    *identity.Identity
	store    *store.Store
	fakeClip *clipboard.FakeClipboard
	pipeline *app.SyncPipeline
	listener *memPipeListener
}

func createSyncNode(t *testing.T, name string, port int) *syncNode {
	t.Helper()

	cfg := config.Defaults()
	cfg.ConfigDir = t.TempDir()
	cfg.DeviceName = name
	cfg.Port = port
	cfg.MaxImageBytes = 10 * 1024 * 1024
	cfg.MaxTextBytes = 1024 * 1024

	ident, err := identity.LoadOrGenerate(cfg.ConfigDir, name)
	if err != nil {
		t.Fatalf("%s: failed to generate identity: %v", name, err)
	}

	st, err := store.New(filepath.Join(cfg.ConfigDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("%s: failed to create store: %v", name, err)
	}

	fakeClip := clipboard.NewFake()

	rawListener := newMemPipeListener(fmt.Sprintf("%s.local:%d", name, port))
	serverTLS := transport.ServerTLSConfig(ident, st)
	tlsListener := tls.NewListener(rawListener, serverTLS)

	pipeline, err := app.NewSyncPipelineWithComponents(&cfg, ident, st, fakeClip, tlsListener)
	if err != nil {
		t.Fatalf("%s: failed to create sync pipeline: %v", name, err)
	}

	return &syncNode{
		name:     name,
		cfg:      &cfg,
		ident:    ident,
		store:    st,
		fakeClip: fakeClip,
		pipeline: pipeline,
		listener: rawListener,
	}
}

// connectSyncClient configures an in-memory mTLS client for caller dialing target.
func connectSyncClient(caller *syncNode, target *syncNode) *transport.Client {
	clientTLS := transport.ClientTLSConfig(caller.ident, caller.store)

	tr := &http.Transport{
		TLSClientConfig: clientTLS,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			select {
			case <-target.listener.closed:
				return nil, net.ErrClosed
			case target.listener.conns <- serverConn:
				return clientConn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 3 * time.Second,
		ForceAttemptHTTP2:     false,
	}

	return transport.NewClientWithHTTPClient(&http.Client{Transport: tr})
}

func TestSync_TwoNode_BidirectionalFullLoop(t *testing.T) {
	nodeA := createSyncNode(t, "mac-node", 47840)
	nodeB := createSyncNode(t, "win-node", 47841)

	// Mutual trust establishment
	now := time.Now()
	_ = nodeA.store.Add(&store.Device{
		ID:          nodeB.ident.DeviceID,
		Name:        nodeB.name,
		OS:          "windows",
		PairedAt:    now,
		LastSeen:    now,
		LastAddress: "win-node.local:47841",
	})
	_ = nodeB.store.Add(&store.Device{
		ID:          nodeA.ident.DeviceID,
		Name:        nodeA.name,
		OS:          "darwin",
		PairedAt:    now,
		LastSeen:    now,
		LastAddress: "mac-node.local:47840",
	})

	// Inject dialed clients and resolvers
	clientA := connectSyncClient(nodeA, nodeB)
	nodeA.pipeline.SetClient(clientA)
	nodeA.pipeline.Resolver().UpdateFromMDNS(nodeB.ident.DeviceID, nodeB.name, discovery.StatusReady, "win-node.local:47841")

	clientB := connectSyncClient(nodeB, nodeA)
	nodeB.pipeline.SetClient(clientB)
	nodeB.pipeline.Resolver().UpdateFromMDNS(nodeA.ident.DeviceID, nodeA.name, discovery.StatusReady, "mac-node.local:47840")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = nodeA.pipeline.Run(ctx) }()
	go func() { _ = nodeB.pipeline.Run(ctx) }()

	// Wait for pipelines to initialize watchers
	time.Sleep(100 * time.Millisecond)

	// 1. Node A copies an image (valid PNG) -> Node B must receive it
	samplePNG := makeMockPNG(10, 10)
	imgItem := &clipboard.Item{
		Kind: clipboard.KindImage,
		Data: samplePNG,
		Mime: "image/png",
	}

	if err := nodeA.fakeClip.Write(imgItem); err != nil {
		t.Fatalf("nodeA failed to write image: %v", err)
	}

	// Poll Node B fake clipboard until image arrives
	var receivedImg *clipboard.Item
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		item, err := nodeB.fakeClip.Read()
		if err == nil && item != nil && item.Kind == clipboard.KindImage {
			receivedImg = item
			break
		}
	}

	if receivedImg == nil {
		t.Fatal("nodeB timed out waiting for synced image from nodeA")
	}
	if !bytes.Equal(receivedImg.Data, samplePNG) {
		t.Fatal("nodeB received corrupted image data")
	}

	// 2. Verify Echo Suppression: Node B must not echo the item back to Node A
	time.Sleep(200 * time.Millisecond)
	// Clear Node A clipboard and confirm no return offer happens
	_ = nodeA.fakeClip.Write(&clipboard.Item{Kind: clipboard.KindText, Data: []byte("initial")})
	time.Sleep(200 * time.Millisecond)
	itemA, _ := nodeA.fakeClip.Read()
	if itemA != nil && itemA.Kind == clipboard.KindImage {
		t.Fatal("echo loop detected: nodeB re-offered image back to nodeA")
	}

	// 3. Node B copies text -> Node A must receive it
	textMsg := "hello from windows clipboard"
	textItem := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte(textMsg),
		Mime: "text/plain; charset=utf-8",
	}

	if err := nodeB.fakeClip.Write(textItem); err != nil {
		t.Fatalf("nodeB failed to write text: %v", err)
	}

	var receivedTxt *clipboard.Item
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		item, err := nodeA.fakeClip.Read()
		if err == nil && item != nil && string(item.Data) == textMsg {
			receivedTxt = item
			break
		}
	}

	if receivedTxt == nil {
		t.Fatal("nodeA timed out waiting for synced text from nodeB")
	}
	if string(receivedTxt.Data) != textMsg {
		t.Fatalf("nodeA text mismatch: got %q, want %q", string(receivedTxt.Data), textMsg)
	}
}

func TestSync_OfflinePeer_ItemDropped(t *testing.T) {
	nodeA := createSyncNode(t, "mac-standalone", 47842)

	// Peer exists in trust store but has no reachable address in resolver
	peerID := "offline-peer-12345"
	_ = nodeA.store.Add(&store.Device{
		ID:   peerID,
		Name: "offline-laptop",
		OS:   "windows",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = nodeA.pipeline.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Copying item while peer is offline must not block or crash
	item := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte("content while offline"),
		Mime: "text/plain; charset=utf-8",
	}

	if err := nodeA.fakeClip.Write(item); err != nil {
		t.Fatalf("failed to write clipboard item: %v", err)
	}

	// Give dispatch worker time to drop item cleanly
	time.Sleep(150 * time.Millisecond)

	// Now bring a second peer online dynamically
	nodeB := createSyncNode(t, "dynamic-laptop", 47844)
	_ = nodeA.store.Add(&store.Device{
		ID:          nodeB.ident.DeviceID,
		Name:        nodeB.name,
		OS:          "windows",
		LastAddress: "dynamic-laptop.local:47844",
	})
	_ = nodeB.store.Add(&store.Device{
		ID:          nodeA.ident.DeviceID,
		Name:        nodeA.name,
		OS:          "darwin",
		LastAddress: "mac-standalone.local:47842",
	})

	clientA := connectSyncClient(nodeA, nodeB)
	nodeA.pipeline.SetClient(clientA)
	nodeA.pipeline.Resolver().UpdateFromMDNS(nodeB.ident.DeviceID, nodeB.name, discovery.StatusReady, "dynamic-laptop.local:47844")

	go func() { _ = nodeB.pipeline.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// When peer comes online, new copies must sync immediately
	newMsg := "syncing after peer came online"
	newItem := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte(newMsg),
		Mime: "text/plain; charset=utf-8",
	}
	if err := nodeA.fakeClip.Write(newItem); err != nil {
		t.Fatalf("failed to write new clipboard item: %v", err)
	}

	var syncedItem *clipboard.Item
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		item, err := nodeB.fakeClip.Read()
		if err == nil && item != nil && string(item.Data) == newMsg {
			syncedItem = item
			break
		}
	}
	if syncedItem == nil {
		t.Fatal("nodeB failed to receive synced item after coming online")
	}
}

func TestSync_TeardownBudget(t *testing.T) {
	node := createSyncNode(t, "shutdown-node", 47843)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- node.pipeline.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	cancel() // Trigger shutdown

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected pipeline error on shutdown: %v", err)
		}
		duration := time.Since(start)
		if duration > 3*time.Second {
			t.Fatalf("teardown took %v; expected < 3s budget", duration)
		}
	case <-time.After(3500 * time.Millisecond):
		t.Fatal("pipeline failed to shut down within 3-second budget")
	}
}
