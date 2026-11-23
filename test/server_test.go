package test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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

type pipeListener struct {
	addr   net.Addr
	ch     chan net.Conn
	done   chan struct{}
	closed bool
	mu     sync.Mutex
}

func newPipeListener(addr string) *pipeListener {
	return &pipeListener{
		addr: &mockAddr{addr: addr},
		ch:   make(chan net.Conn),
		done: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case conn := <-l.ch:
		return conn, nil
	}
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.done)
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return l.addr
}

type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return m.addr }

// setupTestServer creates a Server and backing fake clipboard for HTTP endpoint testing.
func setupTestServer(t *testing.T, imagesOnly bool) (*transport.Server, *clipboard.FakeClipboard, *engine.Engine) {
	t.Helper()

	cfg := config.Defaults()
	cfg.DeviceName = "test-mac"
	cfg.ImagesOnly = imagesOnly
	cfg.MaxImageBytes = 10 * 1024 // 10 KB for test limits
	cfg.MaxTextBytes = 1024       // 1 KB for test limits

	tmpDir := t.TempDir()
	ident, err := identity.LoadOrGenerate(tmpDir, cfg.DeviceName)
	if err != nil {
		t.Fatalf("failed to create test identity: %v", err)
	}

	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	fakeClip := clipboard.NewFake()
	eng := engine.New(&cfg, fakeClip)

	listener := newPipeListener("127.0.0.1:47820")
	srv, err := transport.NewServerWithListener(&cfg, ident, st, eng, listener)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	return srv, fakeClip, eng
}

func TestServer_Ping(t *testing.T) {
	srv, _, _ := setupTestServer(t, false)

	// 1. Missing protocol header
	req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing header, got %d", rr.Code)
	}

	// 2. Mismatched protocol header
	req = httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	req.Header.Set(transport.HeaderProtoVersion, "999")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched header, got %d", rr.Code)
	}

	// 3. Valid ping request
	req = httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var resp transport.PingResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode PingResponse: %v", err)
	}
	if resp.DeviceName != "test-mac" {
		t.Fatalf("expected device_name 'test-mac', got '%s'", resp.DeviceName)
	}
	if resp.ProtocolVersion != 1 {
		t.Fatalf("expected protocol_version 1, got %d", resp.ProtocolVersion)
	}
	if resp.CurrentTime == "" {
		t.Fatal("expected non-empty CurrentTime")
	}
}

func TestServer_Offer(t *testing.T) {
	srv, _, eng := setupTestServer(t, false)

	sendOffer := func(body transport.OfferRequest, protoHeader string) (int, transport.OfferResponse) {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/v1/offer", bytes.NewReader(data))
		if protoHeader != "" {
			req.Header.Set(transport.HeaderProtoVersion, protoHeader)
		}
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)

		var resp transport.OfferResponse
		_ = json.NewDecoder(rr.Body).Decode(&resp)
		return rr.Code, resp
	}

	// 1. Missing header
	code, _ := sendOffer(transport.OfferRequest{Kind: "text", Size: 10}, "")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}

	// 2. Normal text offer -> send
	code, resp := sendOffer(transport.OfferRequest{
		ID:     "1",
		Kind:   "text",
		Size:   100,
		Sha256: "some-unique-hash",
	}, transport.ProtoVersion)
	if code != http.StatusOK || resp.Action != transport.ActionSend {
		t.Fatalf("expected action send, got %+v (code %d)", resp, code)
	}

	// 3. Duplicate check -> skip (duplicate)
	eng.State().SetCurrentLocal("active-clipboard-hash")
	code, resp = sendOffer(transport.OfferRequest{
		ID:     "2",
		Kind:   "text",
		Size:   100,
		Sha256: "active-clipboard-hash",
	}, transport.ProtoVersion)
	if code != http.StatusOK || resp.Action != transport.ActionSkip || resp.Reason != transport.ReasonDuplicate {
		t.Fatalf("expected duplicate skip, got %+v", resp)
	}

	// 4. Too large check -> skip (too_large)
	code, resp = sendOffer(transport.OfferRequest{
		ID:     "3",
		Kind:   "text",
		Size:   5000, // exceeds MaxTextBytes (1024)
		Sha256: "huge-text",
	}, transport.ProtoVersion)
	if code != http.StatusOK || resp.Action != transport.ActionSkip || resp.Reason != transport.ReasonTooLarge {
		t.Fatalf("expected too_large skip, got %+v", resp)
	}

	// 5. Policy check: images-only suppresses text
	srvImagesOnly, _, _ := setupTestServer(t, true)
	data, _ := json.Marshal(transport.OfferRequest{
		ID:     "4",
		Kind:   "text",
		Size:   50,
		Sha256: "text-when-images-only",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/offer", bytes.NewReader(data))
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	rr := httptest.NewRecorder()
	srvImagesOnly.Handler().ServeHTTP(rr, req)

	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Action != transport.ActionSkip || resp.Reason != transport.ReasonKindDisabled {
		t.Fatalf("expected kind_disabled skip, got %+v", resp)
	}
}

func TestServer_Upload(t *testing.T) {
	srv, fakeClip, _ := setupTestServer(t, false)

	// Valid minimal 1x1 PNG bytes
	validPNG := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // signature
		0x00, 0x00, 0x00, 0x0D, // IHDR length = 13
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x00, 0x01, // width = 1
		0x00, 0x00, 0x00, 0x01, // height = 1
		0x08, 0x06, 0x00, 0x00, 0x00, // bit depth, color, compression, filter, interlace
		0x1F, 0x15, 0xC4, 0x89, // CRC
		0x00, 0x00, 0x00, 0x00, // IEND length = 0
		0x49, 0x45, 0x4E, 0x44, // "IEND"
		0xAE, 0x42, 0x60, 0x82, // CRC
	}

	// 1. Missing protocol version
	req := httptest.NewRequest(http.MethodPut, "/v1/items/test-item", bytes.NewReader(validPNG))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing protocol version, got %d", rr.Code)
	}

	// 2. Missing X-Sha256
	req = httptest.NewRequest(http.MethodPut, "/v1/items/test-item", bytes.NewReader(validPNG))
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing X-Sha256, got %d", rr.Code)
	}

	// 3. Mismatched X-Sha256 -> 422 Unprocessable Entity
	req = httptest.NewRequest(http.MethodPut, "/v1/items/test-item", bytes.NewReader(validPNG))
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	req.Header.Set(transport.HeaderSha256, "wrong-digest")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for SHA-256 mismatch, got %d", rr.Code)
	}

	// 4. Invalid PNG image payload -> 400 Bad Request
	corruptedPNG := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFF}
	corruptHash := engine.ComputeHash(corruptedPNG)
	req = httptest.NewRequest(http.MethodPut, "/v1/items/test-item", bytes.NewReader(corruptedPNG))
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	req.Header.Set(transport.HeaderSha256, corruptHash)
	req.Header.Set("Content-Type", "image/png")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for corrupt PNG, got %d", rr.Code)
	}

	// 5. Oversized payload -> 413 Payload Too Large
	oversized := make([]byte, 10*1024+50) // exceeds MaxImageBytes (10 KB)
	oversizedHash := engine.ComputeHash(oversized)
	req = httptest.NewRequest(http.MethodPut, "/v1/items/test-item", bytes.NewReader(oversized))
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	req.Header.Set(transport.HeaderSha256, oversizedHash)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized payload, got %d", rr.Code)
	}

	// 6. Valid text payload upload -> 200 OK
	textBytes := []byte("hello cross-platform clipboard!")
	textHash := engine.ComputeHash(textBytes)
	req = httptest.NewRequest(http.MethodPut, "/v1/items/test-text-1", bytes.NewReader(textBytes))
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	req.Header.Set(transport.HeaderSha256, textHash)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid text upload, got %d", rr.Code)
	}
	appliedText, _ := fakeClip.Read()
	if string(appliedText.Data) != "hello cross-platform clipboard!" {
		t.Fatalf("clipboard received wrong text: %s", string(appliedText.Data))
	}

	// 7. Valid PNG payload upload -> 200 OK
	pngHash := engine.ComputeHash(validPNG)
	req = httptest.NewRequest(http.MethodPut, "/v1/items/test-png-1", bytes.NewReader(validPNG))
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	req.Header.Set(transport.HeaderSha256, pngHash)
	req.Header.Set("Content-Type", "image/png")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid PNG upload, got %d", rr.Code)
	}
	appliedImage, _ := fakeClip.Read()
	if len(appliedImage.Data) != len(validPNG) {
		t.Fatalf("clipboard received wrong image size: %d", len(appliedImage.Data))
	}
}

func TestServer_Lifecycle(t *testing.T) {
	srv, _, _ := setupTestServer(t, false)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	if srv.Addr() == nil {
		t.Fatal("expected non-nil server address")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("failed to stop server: %v", err)
	}
}
