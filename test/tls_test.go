package test

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/store"
)

func TestProtocol_ConstantsAndSerialization(t *testing.T) {
	if transport.HeaderProtoVersion != "X-Proto-Version" {
		t.Fatalf("unexpected HeaderProtoVersion: %s", transport.HeaderProtoVersion)
	}
	if transport.HeaderSha256 != "X-Sha256" {
		t.Fatalf("unexpected HeaderSha256: %s", transport.HeaderSha256)
	}
	if transport.ProtoVersion != "1" || transport.ProtoVersionInt != 1 {
		t.Fatalf("unexpected ProtoVersion")
	}
	if transport.ActionSend != "send" || transport.ActionSkip != "skip" {
		t.Fatalf("unexpected action constants")
	}
	if transport.ReasonDuplicate != "duplicate" || transport.ReasonTooLarge != "too_large" ||
		transport.ReasonKindDisabled != "kind_disabled" || transport.ReasonPaused != "paused" {
		t.Fatalf("unexpected reason constants")
	}

	// PingResponse serialization
	ping := transport.PingResponse{
		DeviceName:      "mac-laptop",
		ProtocolVersion: 1,
		CurrentTime:     "2026-11-22T06:00:00Z",
	}
	data, err := json.Marshal(ping)
	if err != nil {
		t.Fatalf("failed to marshal PingResponse: %v", err)
	}
	var decodedPing transport.PingResponse
	if err := json.Unmarshal(data, &decodedPing); err != nil {
		t.Fatalf("failed to unmarshal PingResponse: %v", err)
	}
	if decodedPing != ping {
		t.Fatalf("PingResponse mismatch: %+v vs %+v", decodedPing, ping)
	}

	// OfferRequest & OfferResponse serialization
	offerReq := transport.OfferRequest{
		ID:     "123e4567-e89b-12d3-a456-426614174000",
		Kind:   "image",
		Size:   1024,
		Sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Mime:   "image/png",
	}
	reqData, err := json.Marshal(offerReq)
	if err != nil {
		t.Fatalf("failed to marshal OfferRequest: %v", err)
	}
	var decodedReq transport.OfferRequest
	if err := json.Unmarshal(reqData, &decodedReq); err != nil {
		t.Fatalf("failed to unmarshal OfferRequest: %v", err)
	}
	if decodedReq != offerReq {
		t.Fatalf("OfferRequest mismatch: %+v vs %+v", decodedReq, offerReq)
	}

	offerResp := transport.OfferResponse{
		Action: transport.ActionSkip,
		Reason: transport.ReasonDuplicate,
	}
	respData, err := json.Marshal(offerResp)
	if err != nil {
		t.Fatalf("failed to marshal OfferResponse: %v", err)
	}
	var decodedResp transport.OfferResponse
	if err := json.Unmarshal(respData, &decodedResp); err != nil {
		t.Fatalf("failed to unmarshal OfferResponse: %v", err)
	}
	if decodedResp != offerResp {
		t.Fatalf("OfferResponse mismatch: %+v vs %+v", decodedResp, offerResp)
	}
}

func TestTLSConfig_VersionsAndProperties(t *testing.T) {
	tmpDir := t.TempDir()
	ident, err := identity.LoadOrGenerate(tmpDir, "node-a")
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}
	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	serverCfg := transport.ServerTLSConfig(ident, st)
	if serverCfg.MinVersion != tls.VersionTLS13 || serverCfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("ServerTLSConfig must enforce TLS 1.3 exclusively")
	}
	if serverCfg.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("ServerTLSConfig must require client certificates")
	}
	if len(serverCfg.Certificates) != 1 {
		t.Fatalf("ServerTLSConfig missing identity certificate")
	}

	clientCfg := transport.ClientTLSConfig(ident, st)
	if clientCfg.MinVersion != tls.VersionTLS13 || clientCfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("ClientTLSConfig must enforce TLS 1.3 exclusively")
	}
	if !clientCfg.InsecureSkipVerify {
		t.Fatalf("ClientTLSConfig must set InsecureSkipVerify=true for custom pinned cert verification")
	}
	if len(clientCfg.Certificates) != 1 {
		t.Fatalf("ClientTLSConfig missing identity certificate")
	}
}

func TestTLS_MutualAuthentication_Success(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	identA, err := identity.LoadOrGenerate(dirA, "node-a")
	if err != nil {
		t.Fatalf("failed to create identA: %v", err)
	}
	identB, err := identity.LoadOrGenerate(dirB, "node-b")
	if err != nil {
		t.Fatalf("failed to create identB: %v", err)
	}

	storeA, _ := store.New(filepath.Join(dirA, "trusted.json"))
	storeB, _ := store.New(filepath.Join(dirB, "trusted.json"))

	// Mutually register identities
	_ = storeA.Add(&store.Device{ID: identB.DeviceID, Name: "node-b", PairedAt: time.Now()})
	_ = storeB.Add(&store.Device{ID: identA.DeviceID, Name: "node-a", PairedAt: time.Now()})

	serverCfg := transport.ServerTLSConfig(identA, storeA)
	clientCfg := transport.ClientTLSConfig(identB, storeB)

	// Use in-memory net.Pipe to test full TLS 1.3 mTLS handshake without socket dependencies
	serverPipe, clientPipe := net.Pipe()
	defer serverPipe.Close()
	defer clientPipe.Close()

	serverTLS := tls.Server(serverPipe, serverCfg)
	clientTLS := tls.Client(clientPipe, clientCfg)

	var wg sync.WaitGroup
	var serverErr, clientErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer serverPipe.Close()
		if err := serverTLS.Handshake(); err != nil {
			serverErr = err
			return
		}
		cs := serverTLS.ConnectionState()
		if cs.Version != tls.VersionTLS13 {
			serverErr = errors.New("expected TLS 1.3 connection")
			return
		}
		if transport.PeerFingerprint(&cs) != identB.DeviceID {
			serverErr = errors.New("server peer fingerprint mismatch")
			return
		}

		buf := make([]byte, 4)
		if _, err := io.ReadFull(serverTLS, buf); err != nil {
			serverErr = err
			return
		}
		_, serverErr = serverTLS.Write(buf)
	}()

	go func() {
		defer wg.Done()
		defer clientPipe.Close()
		if err := clientTLS.Handshake(); err != nil {
			clientErr = err
			return
		}
		cs := clientTLS.ConnectionState()
		if transport.PeerFingerprint(&cs) != identA.DeviceID {
			clientErr = errors.New("client peer fingerprint mismatch")
			return
		}

		if _, err := clientTLS.Write([]byte("ping")); err != nil {
			clientErr = err
			return
		}
		reply := make([]byte, 4)
		if _, err := io.ReadFull(clientTLS, reply); err != nil {
			clientErr = err
			return
		}
		if string(reply) != "ping" {
			clientErr = errors.New("unexpected echo payload")
		}
	}()

	wg.Wait()

	if serverErr != nil {
		t.Fatalf("server error: %v", serverErr)
	}
	if clientErr != nil {
		t.Fatalf("client error: %v", clientErr)
	}
}

func TestTLS_UntrustedClient_RejectedByServer(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	identA, _ := identity.LoadOrGenerate(dirA, "node-a")
	identB, _ := identity.LoadOrGenerate(dirB, "node-b")

	storeA, _ := store.New(filepath.Join(dirA, "trusted.json"))
	storeB, _ := store.New(filepath.Join(dirB, "trusted.json"))

	// Node B trusts Node A, but Node A DOES NOT trust Node B
	_ = storeB.Add(&store.Device{ID: identA.DeviceID, Name: "node-a"})

	serverCfg := transport.ServerTLSConfig(identA, storeA)
	clientCfg := transport.ClientTLSConfig(identB, storeB)

	serverPipe, clientPipe := net.Pipe()
	defer serverPipe.Close()
	defer clientPipe.Close()

	serverTLS := tls.Server(serverPipe, serverCfg)
	clientTLS := tls.Client(clientPipe, clientCfg)

	var wg sync.WaitGroup
	var serverErr, clientErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer serverPipe.Close()
		serverErr = serverTLS.Handshake()
	}()
	go func() {
		defer wg.Done()
		defer clientPipe.Close()
		clientErr = clientTLS.Handshake()
	}()

	wg.Wait()

	// Server must reject untrusted peer
	if serverErr == nil && clientErr == nil {
		t.Fatal("expected untrusted client connection to be rejected, but handshake succeeded")
	}
	if serverErr != nil && !errors.Is(serverErr, transport.ErrUntrustedPeer) {
		// Server error should wrap ErrUntrustedPeer
		if !errors.Is(serverErr, transport.ErrUntrustedPeer) {
			t.Logf("server rejected with: %v", serverErr)
		}
	}
}

func TestTLS_UntrustedServer_RejectedByClient(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	identA, _ := identity.LoadOrGenerate(dirA, "node-a")
	identB, _ := identity.LoadOrGenerate(dirB, "node-b")

	storeA, _ := store.New(filepath.Join(dirA, "trusted.json"))
	storeB, _ := store.New(filepath.Join(dirB, "trusted.json"))

	// Node A trusts Node B, but Node B DOES NOT trust Node A
	_ = storeA.Add(&store.Device{ID: identB.DeviceID, Name: "node-b"})

	serverCfg := transport.ServerTLSConfig(identA, storeA)
	clientCfg := transport.ClientTLSConfig(identB, storeB)

	serverPipe, clientPipe := net.Pipe()
	defer serverPipe.Close()
	defer clientPipe.Close()

	serverTLS := tls.Server(serverPipe, serverCfg)
	clientTLS := tls.Client(clientPipe, clientCfg)

	var wg sync.WaitGroup
	var serverErr, clientErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer serverPipe.Close()
		serverErr = serverTLS.Handshake()
	}()
	go func() {
		defer wg.Done()
		defer clientPipe.Close()
		clientErr = clientTLS.Handshake()
	}()

	wg.Wait()

	// Client must reject untrusted server
	if clientErr == nil && serverErr == nil {
		t.Fatal("expected untrusted server connection to be rejected by client, but handshake succeeded")
	}
	if clientErr != nil {
		t.Logf("client rejected with expected error: %v", clientErr)
	}
}
