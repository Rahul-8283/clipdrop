package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/pairing"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

func newSecurityMTLSClient(ident *identity.Identity, st *store.Store, targetListener *memPipeListener) (*http.Client, *transport.Client) {
	tr := &http.Transport{
		TLSClientConfig: transport.ClientTLSConfig(ident, st),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			select {
			case <-targetListener.closed:
				return nil, net.ErrClosed
			case targetListener.conns <- serverConn:
				return clientConn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 3 * time.Second,
	}
	httpClient := &http.Client{Transport: tr}
	return httpClient, transport.NewClientWithHTTPClient(httpClient)
}

func TestSecurity_IntruderRejection(t *testing.T) {
	// Setup paired Node A and Node B
	dirA := t.TempDir()
	identA, err := identity.LoadOrGenerate(dirA, "sec-node-a")
	if err != nil {
		t.Fatalf("identA: %v", err)
	}
	stA, _ := store.New(filepath.Join(dirA, "trusted_devices.json"))

	dirB := t.TempDir()
	identB, err := identity.LoadOrGenerate(dirB, "sec-node-b")
	if err != nil {
		t.Fatalf("identB: %v", err)
	}
	stB, _ := store.New(filepath.Join(dirB, "trusted_devices.json"))

	// Setup untrusted rogue Node C with its own valid NIST P-256 identity
	dirC := t.TempDir()
	identC, err := identity.LoadOrGenerate(dirC, "rogue-node-c")
	if err != nil {
		t.Fatalf("identC: %v", err)
	}
	stC, _ := store.New(filepath.Join(dirC, "trusted_devices.json"))

	// A and B trust each other; C is NOT in A's store, though C adds A so C completes its client-side check
	_ = stA.Add(&store.Device{ID: identB.DeviceID, Name: "sec-node-b", OS: "windows"})
	_ = stB.Add(&store.Device{ID: identA.DeviceID, Name: "sec-node-a", OS: "darwin"})
	_ = stC.Add(&store.Device{ID: identA.DeviceID, Name: "sec-node-a", OS: "darwin"})

	cfgA := config.Defaults()
	cfgA.ConfigDir = dirA
	cfgA.DeviceName = "sec-node-a"
	clipA := clipboard.NewFake()
	engA := engine.New(&cfgA, clipA)

	rawLn := newMemPipeListener("sec-node-a.local:47870")
	tlsLn := tls.NewListener(rawLn, transport.ServerTLSConfig(identA, stA))
	srvA, err := transport.NewServerWithListener(&cfgA, identA, stA, engA, tlsLn)
	if err != nil {
		t.Fatalf("NewServerWithListener: %v", err)
	}
	if err := srvA.Start(); err != nil {
		t.Fatalf("srvA.Start: %v", err)
	}
	defer func() { _ = srvA.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Confirm trusted Node B succeeds
	_, clientB := newSecurityMTLSClient(identB, stB, rawLn)
	if _, err := clientB.Ping(ctx, "sec-node-a.local:47870"); err != nil {
		t.Fatalf("expected trusted Node B ping to succeed, got: %v", err)
	}

	// Rogue Node C attempts GET /v1/ping, POST /v1/offer, PUT /v1/items/{id}
	_, clientC := newSecurityMTLSClient(identC, stC, rawLn)

	if _, err := clientC.Ping(ctx, "sec-node-a.local:47870"); err == nil {
		t.Fatal("expected rogue Node C Ping to fail TLS 1.3 handshake")
	}

	if _, err := clientC.Offer(ctx, "sec-node-a.local:47870", &transport.OfferRequest{
		ID:     "rogue-offer-1",
		Kind:   "text",
		Size:   13,
		Mime:   "text/plain; charset=utf-8",
		Sha256: engine.ComputeHash([]byte("rogue payload")),
	}); err == nil {
		t.Fatal("expected rogue Node C Offer to fail TLS 1.3 handshake")
	}

	rogueData := []byte("rogue payload")
	if err := clientC.Upload(ctx, "sec-node-a.local:47870", "rogue-item-1", rogueData, clipboard.KindText, "text/plain; charset=utf-8", engine.ComputeHash(rogueData)); err == nil {
		t.Fatal("expected rogue Node C Upload to fail TLS 1.3 handshake")
	}

	// Node A's clipboard must remain completely untouched
	if item, _ := clipA.Read(); item != nil {
		t.Fatalf("security breach: Node A clipboard modified by rogue Node C: %+v", item)
	}
}

func TestSecurity_PayloadTamperingAndValidation(t *testing.T) {
	dirA := t.TempDir()
	identA, _ := identity.LoadOrGenerate(dirA, "val-node-a")
	stA, _ := store.New(filepath.Join(dirA, "trusted_devices.json"))

	dirB := t.TempDir()
	identB, _ := identity.LoadOrGenerate(dirB, "val-node-b")
	stB, _ := store.New(filepath.Join(dirB, "trusted_devices.json"))

	_ = stA.Add(&store.Device{ID: identB.DeviceID, Name: "val-node-b", OS: "windows"})
	_ = stB.Add(&store.Device{ID: identA.DeviceID, Name: "val-node-a", OS: "darwin"})

	cfgA := config.Defaults()
	cfgA.ConfigDir = dirA
	cfgA.DeviceName = "val-node-a"
	clipA := clipboard.NewFake()
	engA := engine.New(&cfgA, clipA)

	rawLn := newMemPipeListener("val-node-a.local:47871")
	tlsLn := tls.NewListener(rawLn, transport.ServerTLSConfig(identA, stA))
	srvA, err := transport.NewServerWithListener(&cfgA, identA, stA, engA, tlsLn)
	if err != nil {
		t.Fatalf("NewServerWithListener: %v", err)
	}
	if err := srvA.Start(); err != nil {
		t.Fatalf("srvA.Start: %v", err)
	}
	defer func() { _ = srvA.Close() }()

	httpClientB, _ := newSecurityMTLSClient(identB, stB, rawLn)

	t.Run("TamperedPayload_HTTP422", func(t *testing.T) {
		original := []byte("original payload bytes")
		expectedSha := engine.ComputeHash(original)

		// Alter 1 byte in transit
		tampered := []byte("original payloae bytes")

		req, _ := http.NewRequest(http.MethodPut, "https://val-node-a.local:47871/v1/items/tamper-1", bytes.NewReader(tampered))
		req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
		req.Header.Set(transport.HeaderSha256, expectedSha)
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")

		resp, err := httpClientB.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("expected HTTP 422 Unprocessable Entity, got %d", resp.StatusCode)
		}
		if item, _ := clipA.Read(); item != nil {
			t.Fatalf("tampered payload must not write to clipboard")
		}
	})

	t.Run("SpoofedPNGHeader_HTTP400", func(t *testing.T) {
		// Valid 8-byte PNG signature followed by corrupted IHDR chunk
		spoofedPNG := []byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG magic
			0x00, 0x00, 0x00, 0x0D, // length 13
			'B', 'A', 'D', 'C', // corrupted chunk type instead of IHDR
			0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
			0x08, 0x06, 0x00, 0x00, 0x00,
		}
		shaHex := engine.ComputeHash(spoofedPNG)

		req, _ := http.NewRequest(http.MethodPut, "https://val-node-a.local:47871/v1/items/spoof-png", bytes.NewReader(spoofedPNG))
		req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
		req.Header.Set(transport.HeaderSha256, shaHex)
		req.Header.Set("Content-Type", "image/png")

		resp, err := httpClientB.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected HTTP 400 Bad Request for spoofed PNG, got %d", resp.StatusCode)
		}
		if item, _ := clipA.Read(); item != nil {
			t.Fatalf("spoofed PNG must not write to clipboard")
		}
	})

	t.Run("OversizedStream_26MB_HTTP413", func(t *testing.T) {
		const size26MB = 26 * 1024 * 1024
		// Stream 26MB of zeros lazily without allocating a separate HTTP buffer copy
		streamReader := io.LimitReader(zeroReader{}, size26MB)

		req, _ := http.NewRequest(http.MethodPut, "https://val-node-a.local:47871/v1/items/oversize-26mb", streamReader)
		req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
		req.Header.Set(transport.HeaderSha256, "0000000000000000000000000000000000000000000000000000000000000000")
		req.Header.Set("Content-Type", "image/png")

		resp, err := httpClientB.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected HTTP 413 Request Entity Too Large for 26MB stream, got %d", resp.StatusCode)
		}
		if item, _ := clipA.Read(); item != nil {
			t.Fatalf("oversized stream must not write to clipboard")
		}
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestSecurity_PairingAttackResistance(t *testing.T) {
	t.Run("BruteForce3WrongAttempts_ClosesListener", func(t *testing.T) {
		hostDir := t.TempDir()
		hostIdent, _ := identity.LoadOrGenerate(hostDir, "sec-pair-host")
		hostStore, _ := store.New(filepath.Join(hostDir, "trusted_devices.json"))

		attackerDir := t.TempDir()
		attackerIdent, _ := identity.LoadOrGenerate(attackerDir, "sec-pair-attacker")
		attackerStore, _ := store.New(filepath.Join(attackerDir, "trusted_devices.json"))

		correctCode := "8412-amber-falcon"
		listener := newMemPipeListener("127.0.0.1:47872")
		host, err := pairing.NewHostWithListener(correctCode, hostIdent, hostStore, listener)
		if err != nil {
			t.Fatalf("NewHostWithListener: %v", err)
		}

		client := createMemClient(listener)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		hostErrCh := make(chan error, 1)
		go func() {
			_, err := host.Serve(ctx)
			hostErrCh <- err
		}()

		wrongCodes := []string{"1111-badger-cedar", "2222-badger-cedar", "3333-badger-cedar"}
		for i, code := range wrongCodes {
			if _, err := pairing.JoinWithHTTPClient(ctx, "127.0.0.1:47872", code, attackerIdent, attackerStore, client); err == nil {
				t.Fatalf("attempt %d unexpectedly succeeded with wrong code", i+1)
			}
		}

		select {
		case hostErr := <-hostErrCh:
			if !errors.Is(hostErr, pairing.ErrMaxAttemptsExceeded) {
				t.Fatalf("expected ErrMaxAttemptsExceeded, got %v", hostErr)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("host did not lock out and close after 3 failed attempts")
		}

		// Even with the correct code, a 4th attempt must be rejected because the listener is closed
		if _, err := pairing.JoinWithHTTPClient(ctx, "127.0.0.1:47872", correctCode, attackerIdent, attackerStore, client); err == nil {
			t.Fatal("expected 4th attempt with correct code to fail after lockout")
		}
	})

	t.Run("ExpiredSession_RejectsLateJoiner", func(t *testing.T) {
		hostDir := t.TempDir()
		hostIdent, _ := identity.LoadOrGenerate(hostDir, "sec-expire-host")
		hostStore, _ := store.New(filepath.Join(hostDir, "trusted_devices.json"))

		joinerDir := t.TempDir()
		joinerIdent, _ := identity.LoadOrGenerate(joinerDir, "sec-late-joiner")
		joinerStore, _ := store.New(filepath.Join(joinerDir, "trusted_devices.json"))

		code := "5510-cobalt-lynx"
		listener := newMemPipeListener("127.0.0.1:47873")
		host, err := pairing.NewHostWithListener(code, hostIdent, hostStore, listener)
		if err != nil {
			t.Fatalf("NewHostWithListener: %v", err)
		}
		host.SetTimeout(50 * time.Millisecond)

		hostErrCh := make(chan error, 1)
		go func() {
			_, err := host.Serve(context.Background())
			hostErrCh <- err
		}()

		select {
		case hostErr := <-hostErrCh:
			if !errors.Is(hostErr, pairing.ErrSessionExpired) {
				t.Fatalf("expected ErrSessionExpired, got %v", hostErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("host did not expire within timeout")
		}

		client := createMemClient(listener)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if _, err := pairing.JoinWithHTTPClient(ctx, "127.0.0.1:47873", code, joinerIdent, joinerStore, client); err == nil {
			t.Fatal("expected late joiner to be rejected after pairing session expired")
		}
	})
}
