package test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

type memPipeListener struct {
	conns     chan net.Conn
	closeOnce sync.Once
	closed    chan struct{}
	addr      net.Addr
}

func newMemPipeListener(addr string) *memPipeListener {
	return &memPipeListener{
		conns:  make(chan net.Conn, 128),
		closed: make(chan struct{}),
		addr:   &mockAddr{addr: addr},
	}
}

func (l *memPipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn, ok := <-l.conns:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *memPipeListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *memPipeListener) Addr() net.Addr { return l.addr }

// testNode bundles server, client, identity, store, and fake clipboard for loopback tests.
type testNode struct {
	name     string
	cfg      *config.Config
	ident    *identity.Identity
	store    *store.Store
	fakeClip *clipboard.FakeClipboard
	eng      *engine.Engine
	listener *memPipeListener
	server   *transport.Server
}

func createTestNode(t *testing.T, name string, modifyCfg ...func(*config.Config)) *testNode {
	t.Helper()

	cfg := config.Defaults()
	cfg.DeviceName = name
	cfg.MaxImageBytes = 10 * 1024 * 1024 // 10 MB for test
	cfg.MaxTextBytes = 1024 * 1024       // 1 MB for test
	for _, fn := range modifyCfg {
		fn(&cfg)
	}

	tmpDir := t.TempDir()
	ident, err := identity.LoadOrGenerate(tmpDir, name)
	if err != nil {
		t.Fatalf("%s: failed to create identity: %v", name, err)
	}

	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("%s: failed to create store: %v", name, err)
	}

	fakeClip := clipboard.NewFake()
	eng := engine.New(&cfg, fakeClip)

	rawListener := newMemPipeListener(fmt.Sprintf("%s.local:47820", name))
	serverTLS := transport.ServerTLSConfig(ident, st)
	tlsListener := tls.NewListener(rawListener, serverTLS)

	server, err := transport.NewServerWithListener(&cfg, ident, st, eng, tlsListener)
	if err != nil {
		t.Fatalf("%s: failed to create server: %v", name, err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("%s: failed to start server: %v", name, err)
	}

	return &testNode{
		name:     name,
		cfg:      &cfg,
		ident:    ident,
		store:    st,
		fakeClip: fakeClip,
		eng:      eng,
		listener: rawListener,
		server:   server,
	}
}

// connectClient configures an mTLS client on caller dialed into target's in-memory listener.
func connectClient(caller *testNode, target *testNode) *transport.Client {
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

// TestTransport_TwoNode_HandshakeAndPing tests mutual authentication and ping between two trusted peers.
func TestTransport_TwoNode_HandshakeAndPing(t *testing.T) {
	nodeA := createTestNode(t, "node-a")
	nodeB := createTestNode(t, "node-b")
	defer nodeA.server.Close()
	defer nodeB.server.Close()

	// Mutually register trust
	_ = nodeA.store.Add(&store.Device{ID: nodeB.ident.DeviceID, Name: nodeB.name, PairedAt: time.Now()})
	_ = nodeB.store.Add(&store.Device{ID: nodeA.ident.DeviceID, Name: nodeA.name, PairedAt: time.Now()})

	clientA := connectClient(nodeA, nodeB)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pingResp, err := clientA.Ping(ctx, nodeB.listener.Addr().String())
	if err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
	if pingResp.DeviceName != "node-b" {
		t.Fatalf("expected device name node-b, got %s", pingResp.DeviceName)
	}
	if pingResp.ProtocolVersion != 1 {
		t.Fatalf("expected protocol version 1, got %d", pingResp.ProtocolVersion)
	}

	// Verify Node B updated LastSeen for Node A
	time.Sleep(10 * time.Millisecond)
	devA, ok := nodeB.store.Get(nodeA.ident.DeviceID)
	if !ok || devA.LastSeen.IsZero() {
		t.Fatal("expected Node B to record LastSeen for Node A upon receiving ping")
	}
}

// TestTransport_UntrustedPeer_Rejection tests that a rogue peer not in store is dropped during mTLS handshake.
func TestTransport_UntrustedPeer_Rejection(t *testing.T) {
	nodeA := createTestNode(t, "node-a")
	nodeC := createTestNode(t, "rogue-c") // NOT added to Node A's store
	defer nodeA.server.Stop(context.Background())
	defer nodeC.server.Stop(context.Background())

	// Rogue C trusts Node A, but Node A does NOT trust Rogue C
	_ = nodeC.store.Add(&store.Device{ID: nodeA.ident.DeviceID, Name: nodeA.name, PairedAt: time.Now()})

	clientC := connectClient(nodeC, nodeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := clientC.Ping(ctx, nodeA.listener.Addr().String())
	if err == nil {
		t.Fatal("expected untrusted peer connection to fail, but succeeded")
	}
}

// TestTransport_OfferAndUpload_Flow tests full offer negotiation, streaming upload, PNG validation, and clipboard write.
func TestTransport_OfferAndUpload_Flow(t *testing.T) {
	nodeA := createTestNode(t, "node-a")
	nodeB := createTestNode(t, "node-b")
	defer nodeA.server.Close()
	defer nodeB.server.Close()

	_ = nodeA.store.Add(&store.Device{ID: nodeB.ident.DeviceID, Name: nodeB.name, PairedAt: time.Now()})
	_ = nodeB.store.Add(&store.Device{ID: nodeA.ident.DeviceID, Name: nodeA.name, PairedAt: time.Now()})

	clientA := connectClient(nodeA, nodeB)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	validPNG := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D,
		0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00,
		0x1F, 0x15, 0xC4, 0x89,
		0x00, 0x00, 0x00, 0x00,
		0x49, 0x45, 0x4E, 0x44,
		0xAE, 0x42, 0x60, 0x82,
	}
	pngHash := engine.ComputeHash(validPNG)

	// 1. Pre-flight offer
	offerReq := &transport.OfferRequest{
		ID:     "item-transfer-01",
		Kind:   "image",
		Size:   int64(len(validPNG)),
		Sha256: pngHash,
		Mime:   "image/png",
	}
	offerResp, err := clientA.Offer(ctx, nodeB.listener.Addr().String(), offerReq)
	if err != nil {
		t.Fatalf("Offer failed: %v", err)
	}
	if offerResp.Action != transport.ActionSend {
		t.Fatalf("expected action send, got %s (reason: %s)", offerResp.Action, offerResp.Reason)
	}

	// 2. Stream upload
	err = clientA.Upload(ctx, nodeB.listener.Addr().String(), offerReq.ID, validPNG,
		clipboard.KindImage, "image/png", pngHash)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// 3. Verify Node B clipboard received item
	appliedItem, err := nodeB.fakeClip.Read()
	if err != nil || appliedItem == nil {
		t.Fatalf("Node B clipboard read failed: %v", err)
	}
	if appliedItem.Kind != clipboard.KindImage || len(appliedItem.Data) != len(validPNG) {
		t.Fatalf("Node B clipboard received incorrect item: %+v", appliedItem)
	}
	if nodeB.eng.State().CurrentLocalHash() != pngHash {
		t.Fatalf("Node B current local hash mismatch: got %s, want %s",
			nodeB.eng.State().CurrentLocalHash(), pngHash)
	}
}

// TestTransport_DuplicateOffer tests receiver suppression when offered item matches current clipboard.
func TestTransport_DuplicateOffer(t *testing.T) {
	nodeA := createTestNode(t, "node-a")
	nodeB := createTestNode(t, "node-b")
	defer nodeA.server.Close()
	defer nodeB.server.Close()

	_ = nodeA.store.Add(&store.Device{ID: nodeB.ident.DeviceID, Name: nodeB.name, PairedAt: time.Now()})
	_ = nodeB.store.Add(&store.Device{ID: nodeA.ident.DeviceID, Name: nodeA.name, PairedAt: time.Now()})

	clientA := connectClient(nodeA, nodeB)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	dupHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	nodeB.eng.State().SetCurrentLocal(dupHash)

	offerReq := &transport.OfferRequest{
		ID:     "item-dup",
		Kind:   "text",
		Size:   64,
		Sha256: dupHash,
	}
	offerResp, err := clientA.Offer(ctx, nodeB.listener.Addr().String(), offerReq)
	if err != nil {
		t.Fatalf("Offer failed: %v", err)
	}
	if offerResp.Action != transport.ActionSkip || offerResp.Reason != transport.ReasonDuplicate {
		t.Fatalf("expected skip (duplicate), got %+v", offerResp)
	}
}

// TestTransport_HashMismatch_Rejection tests receiver rejects upload when SHA-256 header does not match body.
func TestTransport_HashMismatch_Rejection(t *testing.T) {
	nodeA := createTestNode(t, "node-a")
	nodeB := createTestNode(t, "node-b")
	defer nodeA.server.Close()
	defer nodeB.server.Close()

	_ = nodeA.store.Add(&store.Device{ID: nodeB.ident.DeviceID, Name: nodeB.name, PairedAt: time.Now()})
	_ = nodeB.store.Add(&store.Device{ID: nodeA.ident.DeviceID, Name: nodeA.name, PairedAt: time.Now()})

	clientA := connectClient(nodeA, nodeB)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	payload := []byte("legitimate clipboard content")
	tamperedHash := "0000000000000000000000000000000000000000000000000000000000000000"

	err := clientA.Upload(ctx, nodeB.listener.Addr().String(), "mismatch-item", payload,
		clipboard.KindText, "text/plain; charset=utf-8", tamperedHash)
	if err == nil {
		t.Fatal("expected upload error for SHA-256 mismatch, got nil")
	}
	if !errors.Is(err, transport.ErrUnexpectedStatus) || !strings.Contains(err.Error(), "422") {
		t.Fatalf("expected 422 Unprocessable Entity, got: %v", err)
	}
}

// TestTransport_OversizedStream_Rejection tests receiver aborts and returns 413 when body exceeds limits.
func TestTransport_OversizedStream_Rejection(t *testing.T) {
	// Configure Node B with small 5 KB limit for testing
	nodeA := createTestNode(t, "node-a")
	nodeB := createTestNode(t, "node-b", func(c *config.Config) {
		c.MaxImageBytes = 5 * 1024
	})
	defer nodeA.server.Close()
	defer nodeB.server.Close()

	_ = nodeA.store.Add(&store.Device{ID: nodeB.ident.DeviceID, Name: nodeB.name, PairedAt: time.Now()})
	_ = nodeB.store.Add(&store.Device{ID: nodeA.ident.DeviceID, Name: nodeA.name, PairedAt: time.Now()})

	clientA := connectClient(nodeA, nodeB)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	oversizedPayload := make([]byte, 6*1024) // 6 KB > 5 KB limit
	oversizedHash := engine.ComputeHash(oversizedPayload)

	err := clientA.Upload(ctx, nodeB.listener.Addr().String(), "oversized-item", oversizedPayload,
		clipboard.KindText, "text/plain", oversizedHash)
	if err == nil {
		t.Fatal("expected 413 for oversized upload, got nil")
	}
	if !errors.Is(err, transport.ErrUnexpectedStatus) || !strings.Contains(err.Error(), "413") {
		t.Fatalf("expected 413 Payload Too Large, got: %v", err)
	}
}

// TestTransport_ProtocolVersion_Mismatch tests receiver rejects missing or wrong protocol headers with 400.
func TestTransport_ProtocolVersion_Mismatch(t *testing.T) {
	nodeA := createTestNode(t, "node-a")
	nodeB := createTestNode(t, "node-b")
	defer nodeA.server.Close()
	defer nodeB.server.Close()

	_ = nodeA.store.Add(&store.Device{ID: nodeB.ident.DeviceID, Name: nodeB.name, PairedAt: time.Now()})
	_ = nodeB.store.Add(&store.Device{ID: nodeA.ident.DeviceID, Name: nodeA.name, PairedAt: time.Now()})

	clientTLS := transport.ClientTLSConfig(nodeA.ident, nodeA.store)
	tr := &http.Transport{
		TLSClientConfig: clientTLS,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			nodeB.listener.conns <- c2
			return c1, nil
		},
		DisableKeepAlives: true,
	}
	rawClient := &http.Client{Transport: tr}

	// 1. Missing header
	req, _ := http.NewRequest(http.MethodGet, "https://node-b.local:47820/v1/ping", nil)
	resp, err := rawClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing protocol header, got %d", resp.StatusCode)
	}

	// 2. Mismatched header
	req, _ = http.NewRequest(http.MethodGet, "https://node-b.local:47820/v1/ping", nil)
	req.Header.Set(transport.HeaderProtoVersion, "999")
	resp, err = rawClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched protocol header, got %d", resp.StatusCode)
	}
}
