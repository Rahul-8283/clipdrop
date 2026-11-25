package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
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

func TestConcurrency_GoroutineBaselineAndLeakAudit(t *testing.T) {
	// Settle any lingering goroutines from prior tests before capturing baseline.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	nodeA := createSyncNode(t, "leak-mac", 47860)
	nodeB := createSyncNode(t, "leak-win", 47861)

	now := time.Now()
	_ = nodeA.store.Add(&store.Device{
		ID:          nodeB.ident.DeviceID,
		Name:        nodeB.name,
		OS:          "windows",
		PairedAt:    now,
		LastSeen:    now,
		LastAddress: "leak-win.local:47861",
	})
	_ = nodeB.store.Add(&store.Device{
		ID:          nodeA.ident.DeviceID,
		Name:        nodeA.name,
		OS:          "darwin",
		PairedAt:    now,
		LastSeen:    now,
		LastAddress: "leak-mac.local:47860",
	})

	nodeA.pipeline.SetClient(connectSyncClient(nodeA, nodeB))
	nodeA.pipeline.Resolver().UpdateFromMDNS(nodeB.ident.DeviceID, nodeB.name, discovery.StatusReady, "leak-win.local:47861")

	nodeB.pipeline.SetClient(connectSyncClient(nodeB, nodeA))
	nodeB.pipeline.Resolver().UpdateFromMDNS(nodeA.ident.DeviceID, nodeA.name, discovery.StatusReady, "leak-mac.local:47860")

	ctx, cancel := context.WithCancel(context.Background())

	errChA := make(chan error, 1)
	errChB := make(chan error, 1)
	go func() { errChA <- nodeA.pipeline.Run(ctx) }()
	go func() { errChB <- nodeB.pipeline.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)

	// Execute 100 sequential offer + upload cycles from Node A -> Node B.
	for i := 0; i < 100; i++ {
		msg := fmt.Sprintf("sequential-sync-item-%03d", i)
		item := &clipboard.Item{
			Kind: clipboard.KindText,
			Data: []byte(msg),
			Mime: "text/plain; charset=utf-8",
		}
		if err := nodeA.fakeClip.Write(item); err != nil {
			cancel()
			t.Fatalf("iteration %d: nodeA write failed: %v", i, err)
		}

		// Wait for Node B to receive and apply the item.
		received := false
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			got, err := nodeB.fakeClip.Read()
			if err == nil && got != nil && string(got.Data) == msg {
				received = true
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !received {
			cancel()
			t.Fatalf("iteration %d: nodeB timed out waiting for %q", i, msg)
		}
	}

	// Cancel root context and enforce 3-second shutdown budget.
	shutdownStart := time.Now()
	cancel()

	for _, ch := range []chan error{errChA, errChB} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("pipeline returned unexpected error on shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("pipeline failed to shut down within 3-second budget")
		}
	}

	if elapsed := time.Since(shutdownStart); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %v, exceeded 3s budget", elapsed)
	}

	// Assert goroutine count returns to baseline within 3 seconds.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}

	after := runtime.NumGoroutine()
	if after > baseline+2 {
		t.Fatalf("goroutine leak detected: baseline=%d, after=%d", baseline, after)
	}
}

func TestConcurrency_SimultaneousInboundAndOutbound(t *testing.T) {
	nodeA := createSyncNode(t, "race-mac", 47862)
	nodeB := createSyncNode(t, "race-win", 47863)

	now := time.Now()
	_ = nodeA.store.Add(&store.Device{
		ID:          nodeB.ident.DeviceID,
		Name:        nodeB.name,
		OS:          "windows",
		PairedAt:    now,
		LastSeen:    now,
		LastAddress: "race-win.local:47863",
	})
	_ = nodeB.store.Add(&store.Device{
		ID:          nodeA.ident.DeviceID,
		Name:        nodeA.name,
		OS:          "darwin",
		PairedAt:    now,
		LastSeen:    now,
		LastAddress: "race-mac.local:47862",
	})

	nodeA.pipeline.SetClient(connectSyncClient(nodeA, nodeB))
	nodeA.pipeline.Resolver().UpdateFromMDNS(nodeB.ident.DeviceID, nodeB.name, discovery.StatusReady, "race-win.local:47863")

	nodeB.pipeline.SetClient(connectSyncClient(nodeB, nodeA))
	nodeB.pipeline.Resolver().UpdateFromMDNS(nodeA.ident.DeviceID, nodeA.name, discovery.StatusReady, "race-mac.local:47862")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChA := make(chan error, 1)
	errChB := make(chan error, 1)
	go func() { errChA <- nodeA.pipeline.Run(ctx) }()
	go func() { errChB <- nodeB.pipeline.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)

	// Trigger simultaneous outbound copy on Node A and inbound stream from Node B across 10 rounds.
	for round := 0; round < 10; round++ {
		var wg sync.WaitGroup
		startBarrier := make(chan struct{})

		wg.Add(2)
		go func(r int) {
			defer wg.Done()
			<-startBarrier
			_ = nodeA.fakeClip.Write(&clipboard.Item{
				Kind: clipboard.KindText,
				Data: fmt.Appendf(nil, "from-mac-round-%d", r),
				Mime: "text/plain; charset=utf-8",
			})
		}(round)

		go func(r int) {
			defer wg.Done()
			<-startBarrier
			_ = nodeB.fakeClip.Write(&clipboard.Item{
				Kind: clipboard.KindText,
				Data: fmt.Appendf(nil, "from-win-round-%d", r),
				Mime: "text/plain; charset=utf-8",
			})
		}(round)

		close(startBarrier)
		wg.Wait()
		time.Sleep(40 * time.Millisecond)
	}

	cancel()
	for _, ch := range []chan error{errChA, errChB} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("unexpected pipeline error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("pipeline failed to stop within 3s after concurrent transfers")
		}
	}
}

func TestConcurrency_RoutingTableAndPresence(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	peerIDs := []string{
		"peer-concurrency-01",
		"peer-concurrency-02",
		"peer-concurrency-03",
		"peer-concurrency-04",
		"peer-concurrency-05",
	}
	for i, id := range peerIDs {
		_ = st.Add(&store.Device{
			ID:          id,
			Name:        fmt.Sprintf("peer-%d", i),
			OS:          "windows",
			LastAddress: fmt.Sprintf("192.168.1.%d:47820", 10+i),
		})
	}

	cfg := config.Defaults()
	resolver := discovery.NewResolver(&cfg, st)
	pinger := &mockPinger{}
	pm := app.NewPresenceMonitorWithPinger(&cfg, st, pinger, resolver)
	pm.SetInterval(5 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup

	// PresenceMonitor heartbeat loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = pm.Start(ctx)
	}()

	// Concurrent mDNS resolver mutators and readers
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			i := 0
			for ctx.Err() == nil {
				id := peerIDs[i%len(peerIDs)]
				if i%3 == 0 {
					resolver.RemoveMDNS(id)
				} else {
					resolver.UpdateFromMDNS(id, fmt.Sprintf("peer-%d", w), discovery.StatusReady, fmt.Sprintf("192.168.1.%d:47820", 50+((i+w)%50)))
				}
				_, _ = resolver.Resolve(id)
				_ = resolver.OnlinePeers()
				_ = pm.IsOnline(id)
				i++
				time.Sleep(2 * time.Millisecond)
			}
		}(worker)
	}

	wg.Wait()
}

type throttledConn struct {
	net.Conn
	bytesWritten atomic.Int64
	onThreshold  func()
	threshold    int64
	triggered    atomic.Bool
}

func (c *throttledConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	total := c.bytesWritten.Add(int64(n))
	if total >= c.threshold && c.onThreshold != nil && c.triggered.CompareAndSwap(false, true) {
		c.onThreshold()
	}
	// Slight pacing so cancellation intersects active streaming
	time.Sleep(2 * time.Millisecond)
	return n, err
}

func TestConcurrency_MidTransferCancellation(t *testing.T) {
	cfgA := config.Defaults()
	cfgA.ConfigDir = t.TempDir()
	cfgA.DeviceName = "cancel-client"
	identA, err := identity.LoadOrGenerate(cfgA.ConfigDir, cfgA.DeviceName)
	if err != nil {
		t.Fatalf("identA: %v", err)
	}
	stA, _ := store.New(filepath.Join(cfgA.ConfigDir, "trusted_devices.json"))

	cfgB := config.Defaults()
	cfgB.ConfigDir = t.TempDir()
	cfgB.DeviceName = "cancel-server"
	identB, err := identity.LoadOrGenerate(cfgB.ConfigDir, cfgB.DeviceName)
	if err != nil {
		t.Fatalf("identB: %v", err)
	}
	stB, _ := store.New(filepath.Join(cfgB.ConfigDir, "trusted_devices.json"))

	_ = stA.Add(&store.Device{ID: identB.DeviceID, Name: cfgB.DeviceName, OS: "windows", LastAddress: "cancel-server.local:47864"})
	_ = stB.Add(&store.Device{ID: identA.DeviceID, Name: cfgA.DeviceName, OS: "darwin", LastAddress: "cancel-client.local:47865"})

	rawListener := newMemPipeListener("cancel-server.local:47864")
	tlsListener := tls.NewListener(rawListener, transport.ServerTLSConfig(identB, stB))

	fakeClipB := clipboard.NewFake()
	engB := engine.New(&cfgB, fakeClipB)
	srvB, err := transport.NewServerWithListener(&cfgB, identB, stB, engB, tlsListener)
	if err != nil {
		t.Fatalf("NewServerWithListener: %v", err)
	}
	if err := srvB.Start(); err != nil {
		t.Fatalf("srvB.Start: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	tr := &http.Transport{
		TLSClientConfig: transport.ClientTLSConfig(identA, stA),
		DialContext: func(dCtx context.Context, network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			select {
			case <-rawListener.closed:
				return nil, net.ErrClosed
			case rawListener.conns <- serverConn:
				return &throttledConn{
					Conn:      clientConn,
					threshold: 512 * 1024, // Cancel once 512KB of the multi-MB stream has been written
					onThreshold: func() {
						cancel()
					},
				}, nil
			case <-dCtx.Done():
				return nil, dCtx.Err()
			}
		},
		DisableKeepAlives: true,
	}
	clientA := transport.NewClientWithHTTPClient(&http.Client{Transport: tr})

	// Build a 4MB valid-size payload for mid-stream cancellation
	payload := bytes.Repeat([]byte("A"), 4*1024*1024)
	hash := engine.ComputeHash(payload)

	uploadErrCh := make(chan error, 1)
	go func() {
		uploadErrCh <- clientA.Upload(ctx, "cancel-server.local:47864", "mid-cancel-1", payload, clipboard.KindText, "text/plain; charset=utf-8", hash)
	}()

	// Wait for upload to abort on cancellation
	select {
	case err := <-uploadErrCh:
		if err == nil {
			t.Fatal("expected upload to return error upon mid-transfer cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client upload did not abort within 3s on context cancellation")
	}

	// Verify server stops cleanly within 3-second shutdown budget
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- srvB.Stop(stopCtx)
	}()

	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("server Stop returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server failed to shut down within 3-second budget")
	}

	// Partial upload must never pollute receiver's clipboard
	if item, _ := fakeClipB.Read(); item != nil {
		t.Fatalf("expected receiver clipboard to remain empty after cancelled upload, got %d bytes", len(item.Data))
	}
}
