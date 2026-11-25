package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

func setupBenchmarkPair(tb testing.TB) (*transport.Client, *clipboard.FakeClipboard, string, func()) {
	tb.Helper()

	dirA := tb.TempDir()
	identA, err := identity.LoadOrGenerate(dirA, "bench-node-a")
	if err != nil {
		tb.Fatalf("identA: %v", err)
	}
	stA, _ := store.New(filepath.Join(dirA, "trusted_devices.json"))

	dirB := tb.TempDir()
	identB, err := identity.LoadOrGenerate(dirB, "bench-node-b")
	if err != nil {
		tb.Fatalf("identB: %v", err)
	}
	stB, _ := store.New(filepath.Join(dirB, "trusted_devices.json"))

	_ = stA.Add(&store.Device{ID: identB.DeviceID, Name: "bench-node-b", OS: "windows"})
	_ = stB.Add(&store.Device{ID: identA.DeviceID, Name: "bench-node-a", OS: "darwin"})

	cfgB := config.Defaults()
	cfgB.ConfigDir = dirB
	cfgB.DeviceName = "bench-node-b"
	clipB := clipboard.NewFake()
	engB := engine.New(&cfgB, clipB)

	const addr = "bench-node-b.local:47890"
	rawLn := newMemPipeListener(addr)
	srvB, err := transport.NewServerWithListener(&cfgB, identB, stB, engB, tls.NewListener(rawLn, transport.ServerTLSConfig(identB, stB)))
	if err != nil {
		tb.Fatalf("NewServerWithListener: %v", err)
	}
	if err := srvB.Start(); err != nil {
		tb.Fatalf("srvB.Start: %v", err)
	}

	tr := &http.Transport{
		TLSClientConfig: transport.ClientTLSConfig(identA, stA),
		DialContext: func(ctx context.Context, network, dAddr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			select {
			case <-rawLn.closed:
				return nil, net.ErrClosed
			case rawLn.conns <- serverConn:
				return clientConn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	clientA := transport.NewClientWithHTTPClient(&http.Client{Transport: tr})

	cleanup := func() {
		time.Sleep(50 * time.Millisecond) // allow background retention writes to finish before TempDir cleanup
		_ = srvB.Close()
	}

	return clientA, clipB, addr, cleanup
}

func makeSizedMockPNG(size int) []byte {
	header := makeMockPNG(1920, 1080)
	buf := make([]byte, size)
	copy(buf, header)
	return buf
}

func BenchmarkSync_Text50KB(b *testing.B) {
	clientA, clipB, addr, cleanup := setupBenchmarkPair(b)
	defer cleanup()

	payload := bytes.Repeat([]byte("A"), 50*1024)
	ctx := context.Background()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Mutate prefix per iteration so deduplication never skips an iteration
		binary.BigEndian.PutUint64(payload[:8], uint64(i+1))
		// Keep valid UTF-8 by masking high bits on the 8-byte prefix
		for j := 0; j < 8; j++ {
			payload[j] = 'a' + (payload[j] % 26)
		}

		sha := engine.ComputeHash(payload)
		id := fmt.Sprintf("bench-txt-%d", i)

		resp, err := clientA.Offer(ctx, addr, &transport.OfferRequest{
			ID:     id,
			Kind:   string(clipboard.KindText),
			Size:   int64(len(payload)),
			Mime:   "text/plain; charset=utf-8",
			Sha256: sha,
		})
		if err != nil {
			b.Fatalf("Offer failed: %v", err)
		}
		if resp.Action != transport.ActionSend {
			b.Fatalf("expected ActionSend, got %q (%s)", resp.Action, resp.Reason)
		}

		if err := clientA.Upload(ctx, addr, id, payload, clipboard.KindText, "text/plain; charset=utf-8", sha); err != nil {
			b.Fatalf("Upload failed: %v", err)
		}

		if got, err := clipB.Read(); err != nil || got == nil || len(got.Data) != len(payload) {
			b.Fatalf("clipboard apply verification failed: err=%v", err)
		}
	}

	b.StopTimer()
	if b.N > 0 {
		avg := b.Elapsed() / time.Duration(b.N)
		if avg > 500*time.Millisecond {
			b.Fatalf("50KB text sync average latency %v exceeded 500ms budget", avg)
		}
	}
}

func BenchmarkSync_Image5MB(b *testing.B) {
	clientA, clipB, addr, cleanup := setupBenchmarkPair(b)
	defer cleanup()

	const size5MB = 5 * 1024 * 1024
	payload := makeSizedMockPNG(size5MB)
	ctx := context.Background()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(payload[len(payload)-8:], uint64(i+1))
		sha := engine.ComputeHash(payload)
		id := fmt.Sprintf("bench-img-%d", i)

		resp, err := clientA.Offer(ctx, addr, &transport.OfferRequest{
			ID:     id,
			Kind:   string(clipboard.KindImage),
			Size:   int64(len(payload)),
			Mime:   "image/png",
			Sha256: sha,
		})
		if err != nil {
			b.Fatalf("Offer failed: %v", err)
		}
		if resp.Action != transport.ActionSend {
			b.Fatalf("expected ActionSend, got %q (%s)", resp.Action, resp.Reason)
		}

		if err := clientA.Upload(ctx, addr, id, payload, clipboard.KindImage, "image/png", sha); err != nil {
			b.Fatalf("Upload failed: %v", err)
		}

		if got, err := clipB.Read(); err != nil || got == nil || len(got.Data) != len(payload) {
			b.Fatalf("clipboard apply verification failed: err=%v", err)
		}
	}

	b.StopTimer()
	if b.N > 0 {
		avg := b.Elapsed() / time.Duration(b.N)
		if avg > 2*time.Second {
			b.Fatalf("5MB image sync average latency %v exceeded 2.0s budget", avg)
		}
	}
}

func TestBenchmark_MemoryStability50Transfers(t *testing.T) {
	clientA, clipB, addr, cleanup := setupBenchmarkPair(t)
	defer cleanup()

	const size1_5MB = 1536 * 1024 // 1.5MB per transfer (>1MB)
	payload := makeSizedMockPNG(size1_5MB)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Warm up one transfer so one-time TLS/HTTP pool structures are allocated before baseline
	binary.BigEndian.PutUint64(payload[len(payload)-8:], 99999)
	warmSha := engine.ComputeHash(payload)
	if resp, err := clientA.Offer(ctx, addr, &transport.OfferRequest{
		ID:     "warmup",
		Kind:   string(clipboard.KindImage),
		Size:   int64(len(payload)),
		Mime:   "image/png",
		Sha256: warmSha,
	}); err != nil || resp.Action != transport.ActionSend {
		t.Fatalf("warmup offer failed: err=%v resp=%+v", err, resp)
	}
	if err := clientA.Upload(ctx, addr, "warmup", payload, clipboard.KindImage, "image/png", warmSha); err != nil {
		t.Fatalf("warmup upload failed: %v", err)
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	var baseStats runtime.MemStats
	runtime.ReadMemStats(&baseStats)

	// Perform 50 consecutive 1.5MB transfers
	for i := 0; i < 50; i++ {
		binary.BigEndian.PutUint64(payload[len(payload)-8:], uint64(i+1))
		sha := engine.ComputeHash(payload)
		id := fmt.Sprintf("mem-img-%d", i)

		resp, err := clientA.Offer(ctx, addr, &transport.OfferRequest{
			ID:     id,
			Kind:   string(clipboard.KindImage),
			Size:   int64(len(payload)),
			Mime:   "image/png",
			Sha256: sha,
		})
		if err != nil {
			t.Fatalf("transfer %d Offer failed: %v", i, err)
		}
		if resp.Action != transport.ActionSend {
			t.Fatalf("transfer %d expected ActionSend, got %q", i, resp.Action)
		}
		if err := clientA.Upload(ctx, addr, id, payload, clipboard.KindImage, "image/png", sha); err != nil {
			t.Fatalf("transfer %d Upload failed: %v", i, err)
		}
		if got, err := clipB.Read(); err != nil || got == nil || len(got.Data) != len(payload) {
			t.Fatalf("transfer %d clipboard mismatch: err=%v", i, err)
		}
	}

	// Wait briefly for async retention pruning, then force GC and inspect HeapAlloc
	time.Sleep(150 * time.Millisecond)
	runtime.GC()
	runtime.GC()

	var afterStats runtime.MemStats
	runtime.ReadMemStats(&afterStats)

	var growth int64
	if afterStats.HeapAlloc > baseStats.HeapAlloc {
		growth = int64(afterStats.HeapAlloc - baseStats.HeapAlloc)
	}

	t.Logf("HeapAlloc baseline=%d KB, after 50x1.5MB transfers=%d KB, growth=%d KB",
		baseStats.HeapAlloc/1024, afterStats.HeapAlloc/1024, growth/1024)

	const maxAllowedGrowth = 5 * 1024 * 1024 // 5MB
	if growth > maxAllowedGrowth {
		t.Fatalf("heap growth %d bytes exceeded 5MB bound (baseline=%d, after=%d)", growth, baseStats.HeapAlloc, afterStats.HeapAlloc)
	}
}
