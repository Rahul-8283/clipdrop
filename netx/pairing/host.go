package pairing

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/store"
)

// Pairing host and session errors.
var (
	ErrSessionExpired      = errors.New("pairing: session expired (120-second timeout)")
	ErrMaxAttemptsExceeded = errors.New("pairing: maximum failed attempts exceeded (locked out)")
	ErrHostClosed          = errors.New("pairing: host pairing server closed")
)

const (
	// MaxPairingAttempts defines the brute-force attempt lockout threshold.
	MaxPairingAttempts = 3

	// DefaultSessionTimeout defines the lifetime of an ephemeral pairing host.
	DefaultSessionTimeout = 120 * time.Second
)

// PakeInitResponse carries the host's public point A to the joiner.
type PakeInitResponse struct {
	PointA string `json:"point_a"`
}

// PakeExchangeRequest carries the joiner's public point B to the host.
type PakeExchangeRequest struct {
	PointB string `json:"point_b"`
}

// PakeExchangeResponse indicates acceptance of point B.
type PakeExchangeResponse struct {
	Status string `json:"status"`
}

// EncryptedPayloadWrapper wraps hex-encoded AES-GCM credentials.
type EncryptedPayloadWrapper struct {
	Payload string `json:"payload"`
}

// Host coordinates the ephemeral HTTP pairing server.
type Host struct {
	code        string
	ident       *identity.Identity
	store       *store.Store
	listener    net.Listener
	httpServer  *http.Server
	session     *Session
	pointA      []byte
	sessionKey  []byte
	attempts    int32
	mu          sync.Mutex
	doneCh      chan struct{}
	pairedDev   *store.Device
	err         error
	closeOnce   sync.Once
	timeout     time.Duration
}

// NewHost creates an ephemeral pairing host bound to a dynamic port (:0).
func NewHost(code string, ident *identity.Identity, st *store.Store) (*Host, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to bind ephemeral listener: %w", err)
	}
	return NewHostWithListener(code, ident, st, listener)
}

// NewHostWithListener constructs an ephemeral pairing host with a custom net.Listener.
func NewHostWithListener(code string, ident *identity.Identity, st *store.Store, listener net.Listener) (*Host, error) {
	if ident == nil || st == nil || listener == nil {
		return nil, errors.New("pairing: identity, store, and listener are required")
	}

	normCode := NormalizeCode(code)
	if normCode == "" {
		return nil, ErrInvalidCode
	}

	session, pointA, err := InitHost(normCode)
	if err != nil {
		return nil, err
	}

	h := &Host{
		code:       normCode,
		ident:      ident,
		store:      st,
		listener:   listener,
		session:    session,
		pointA:     pointA,
		doneCh:     make(chan struct{}),
		timeout:    DefaultSessionTimeout,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/pair/pake", h.handleGetPointA)
	mux.HandleFunc("POST /v1/pair/pake", h.handlePostPointB)
	mux.HandleFunc("POST /v1/pair/exchange", h.handleExchange)

	h.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return h, nil
}

// SetTimeout overrides the default 120-second expiration timeout (useful for tests).
func (h *Host) SetTimeout(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.timeout = d
}

// Addr returns the listening address of the pairing host.
func (h *Host) Addr() net.Addr {
	if h.listener != nil {
		return h.listener.Addr()
	}
	return nil
}

// Port returns the listening port number of the ephemeral server.
func (h *Host) Port() int {
	if h.listener != nil {
		if tcpAddr, ok := h.listener.Addr().(*net.TCPAddr); ok {
			return tcpAddr.Port
		}
	}
	return 0
}

// Code returns the normalized pairing code.
func (h *Host) Code() string {
	return h.code
}

// Serve starts the ephemeral pairing server and blocks until pairing succeeds,
// maximum failed attempts are reached, or the session expires.
func (h *Host) Serve(ctx context.Context) (*store.Device, error) {
	h.mu.Lock()
	timeout := h.timeout
	h.mu.Unlock()

	sessionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Run HTTP server accept loop in background
	serverErrCh := make(chan error, 1)
	go func() {
		if err := h.httpServer.Serve(h.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	select {
	case <-sessionCtx.Done():
		h.Close()
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, ErrSessionExpired

	case err := <-serverErrCh:
		h.Close()
		return nil, fmt.Errorf("pairing: server error: %w", err)

	case <-h.doneCh:
		h.Close()
		h.mu.Lock()
		dev, err := h.pairedDev, h.err
		h.mu.Unlock()
		return dev, err
	}
}

// Close gracefully closes the pairing host listener and releases resources.
func (h *Host) Close() error {
	var err error
	h.closeOnce.Do(func() {
		err = h.httpServer.Close()
	})
	return err
}

// handleGetPointA returns the host's public PAKE point A to the joiner.
func (h *Host) handleGetPointA(w http.ResponseWriter, r *http.Request) {
	resp := PakeInitResponse{
		PointA: hex.EncodeToString(h.pointA),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handlePostPointB ingests joiner's point B and derives the PAKE symmetric key.
func (h *Host) handlePostPointB(w http.ResponseWriter, r *http.Request) {
	var req PakeExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	pointB, err := hex.DecodeString(req.PointB)
	if err != nil || len(pointB) == 0 {
		http.Error(w, "invalid point B format", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	key, err := CompleteHost(h.session, pointB)
	if err != nil {
		h.recordFailureLocked("PAKE point B completion failed")
		http.Error(w, "handshake failed", http.StatusBadRequest)
		return
	}

	h.sessionKey = key

	resp := PakeExchangeResponse{Status: "ok"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleExchange verifies encrypted joiner credentials and responds with host credentials.
func (h *Host) handleExchange(w http.ResponseWriter, r *http.Request) {
	var wrapper EncryptedPayloadWrapper
	if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}

	ciphertext, err := hex.DecodeString(wrapper.Payload)
	if err != nil || len(ciphertext) == 0 {
		http.Error(w, "invalid ciphertext format", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.sessionKey) == 0 {
		http.Error(w, "session key not established", http.StatusBadRequest)
		return
	}

	// Decrypt joiner credentials with derived PAKE key
	creds, err := DecryptCredentials(ciphertext, h.sessionKey)
	if err != nil {
		h.recordFailureLocked(fmt.Sprintf("credential decryption failed: %v", err))
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Register peer in local trust store
	now := time.Now()
	peerDevice := &store.Device{
		ID:          creds.DeviceID,
		Name:        creds.Name,
		OS:          creds.OS,
		PairedAt:    now,
		LastSeen:    now,
		LastAddress: r.RemoteAddr,
	}

	if err := h.store.Add(peerDevice); err != nil {
		http.Error(w, "failed to persist peer trust", http.StatusInternalServerError)
		return
	}

	// Prepare and encrypt host credentials to return
	hostName := h.ident.Certificate.Subject.CommonName
	if hostName == "" {
		hostName = "clipdrop-host"
	}

	hostCreds := &Credentials{
		DeviceID: h.ident.DeviceID,
		Name:     hostName,
		OS:       runtime.GOOS,
	}

	hostCiphertext, err := EncryptCredentials(hostCreds, h.sessionKey)
	if err != nil {
		http.Error(w, "failed to encrypt host credentials", http.StatusInternalServerError)
		return
	}

	resp := EncryptedPayloadWrapper{
		Payload: hex.EncodeToString(hostCiphertext),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Single-use guarantee: trigger success completion
	h.pairedDev = peerDevice
	h.err = nil
	go func() {
		// Yield briefly so the client receives the full HTTP response before listener shutdown
		time.Sleep(50 * time.Millisecond)
		select {
		case <-h.doneCh:
		default:
			close(h.doneCh)
		}
	}()
}

// recordFailureLocked registers a failed attempt and triggers lockout if >= 3 failures.
func (h *Host) recordFailureLocked(reason string) {
	attempts := atomic.AddInt32(&h.attempts, 1)
	if attempts >= MaxPairingAttempts {
		h.err = ErrMaxAttemptsExceeded
		go func() {
			time.Sleep(50 * time.Millisecond)
			select {
			case <-h.doneCh:
			default:
				close(h.doneCh)
			}
		}()
	}
}
