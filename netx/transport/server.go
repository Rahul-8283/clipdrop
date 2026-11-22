package transport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/imaging"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

// Server implements the mTLS HTTP/1.1 sync server handling peer ping,
// transfer offers, and binary payload uploads.
type Server struct {
	cfg       *config.Config
	ident     *identity.Identity
	store     *store.Store
	eng       *engine.Engine
	listener  net.Listener
	httpSrv   *http.Server
	startOnce sync.Once
}

// NewServer creates a new TLS-enabled sync server bound to the configured port.
func NewServer(cfg *config.Config, ident *identity.Identity, st *store.Store, eng *engine.Engine) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("server: config is required")
	}
	if ident == nil {
		return nil, errors.New("server: identity is required")
	}
	if st == nil {
		return nil, errors.New("server: store is required")
	}
	if eng == nil {
		return nil, errors.New("server: engine is required")
	}

	tlsConfig := ServerTLSConfig(ident, st)
	addr := fmt.Sprintf(":%d", cfg.Port)
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("server: failed to bind listener on %s: %w", addr, err)
	}

	return NewServerWithListener(cfg, ident, st, eng, listener)
}

// NewServerWithListener constructs a Server using a pre-existing listener (e.g., for testing).
func NewServerWithListener(cfg *config.Config, ident *identity.Identity, st *store.Store, eng *engine.Engine, listener net.Listener) (*Server, error) {
	if cfg == nil || ident == nil || st == nil || eng == nil || listener == nil {
		return nil, errors.New("server: all arguments are required")
	}

	s := &Server{
		cfg:      cfg,
		ident:    ident,
		store:    st,
		eng:      eng,
		listener: listener,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ping", s.handlePing)
	mux.HandleFunc("POST /v1/offer", s.handleOffer)
	mux.HandleFunc("PUT /v1/items/{id}", s.handleUpload)

	s.httpSrv = &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// Addr returns the network address the server is listening on.
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Handler returns the HTTP handler backing the server endpoints.
func (s *Server) Handler() http.Handler {
	return s.httpSrv.Handler
}

// Start initiates the server's HTTP accept loop in a background goroutine.
func (s *Server) Start() error {
	s.startOnce.Do(func() {
		go func() {
			if err := s.httpSrv.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("server: http serve error", "err", err)
			}
		}()
	})
	return nil
}

// Stop gracefully shuts down the server, draining active connections within ctx.
func (s *Server) Stop(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// handlePing processes GET /v1/ping requests.
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(HeaderProtoVersion) != ProtoVersion {
		http.Error(w, "invalid or missing protocol version", http.StatusBadRequest)
		return
	}

	s.recordPeerActivity(r)

	resp := PingResponse{
		DeviceName:      s.cfg.DeviceName,
		ProtocolVersion: ProtoVersionInt,
		CurrentTime:     time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleOffer processes POST /v1/offer requests.
func (s *Server) handleOffer(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(HeaderProtoVersion) != ProtoVersion {
		http.Error(w, "invalid or missing protocol version", http.StatusBadRequest)
		return
	}

	s.recordPeerActivity(r)

	var req OfferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	var resp OfferResponse

	isText := req.Kind == "text" || req.Kind == string(clipboard.KindText)
	isImage := req.Kind == "image" || req.Kind == string(clipboard.KindImage)

	maxImg := s.cfg.MaxImageBytes
	if maxImg <= 0 {
		maxImg = imaging.MaxImageBytes
	}
	maxTxt := s.cfg.MaxTextBytes
	if maxTxt <= 0 {
		maxTxt = 1_048_576 // 1MB default
	}

	// 1. Kind policy check
	if isText && (s.cfg.ImagesOnly || s.cfg.NoText) {
		resp = OfferResponse{
			Action: ActionSkip,
			Reason: ReasonKindDisabled,
		}
	} else if (isImage && req.Size > maxImg) || (isText && req.Size > maxTxt) || (req.Size > maxImg) {
		// 2. Payload size check
		resp = OfferResponse{
			Action: ActionSkip,
			Reason: ReasonTooLarge,
		}
	} else if req.Sha256 != "" && req.Sha256 == s.eng.State().CurrentLocalHash() {
		// 3. Deduplication check against receiver's current clipboard
		resp = OfferResponse{
			Action: ActionSkip,
			Reason: ReasonDuplicate,
		}
	} else {
		// 4. Accept transfer
		resp = OfferResponse{
			Action: ActionSend,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleUpload processes PUT /v1/items/{id} streaming payload requests.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(HeaderProtoVersion) != ProtoVersion {
		http.Error(w, "invalid or missing protocol version", http.StatusBadRequest)
		return
	}

	headerSha := strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderSha256)))
	if headerSha == "" {
		http.Error(w, "missing X-Sha256 header", http.StatusBadRequest)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		id = strings.TrimPrefix(r.URL.Path, "/v1/items/")
	}
	if id == "" || id == "/" {
		http.Error(w, "missing item ID", http.StatusBadRequest)
		return
	}

	s.recordPeerActivity(r)

	maxLimit := s.cfg.MaxImageBytes
	if maxLimit <= 0 {
		maxLimit = imaging.MaxImageBytes
	}

	// Read request body capped at maxLimit + 1 byte
	lr := io.LimitReader(r.Body, maxLimit+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		http.Error(w, "failed to read upload payload", http.StatusBadRequest)
		return
	}

	if int64(len(data)) > maxLimit {
		http.Error(w, "payload exceeds maximum permissible size", http.StatusRequestEntityTooLarge)
		return
	}

	// Verify SHA-256 digest
	computedSha := engine.ComputeHash(data)
	if computedSha != headerSha {
		http.Error(w, "SHA-256 digest mismatch", http.StatusUnprocessableEntity)
		return
	}

	// Classify payload kind
	ct := r.Header.Get("Content-Type")
	var kind clipboard.ItemKind

	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "image/png") {
		if _, err := imaging.ValidatePNG(data); err != nil {
			http.Error(w, fmt.Sprintf("invalid PNG data: %v", err), http.StatusBadRequest)
			return
		}
		kind = clipboard.KindImage
	} else if strings.HasPrefix(ct, "text/") {
		if s.cfg.ImagesOnly || s.cfg.NoText {
			http.Error(w, "text synchronization is disabled on this device", http.StatusBadRequest)
			return
		}
		kind = clipboard.KindText
	} else {
		// Fallback: check if content is valid PNG, otherwise treat as text
		if _, err := imaging.ValidatePNG(data); err == nil {
			kind = clipboard.KindImage
		} else {
			if s.cfg.ImagesOnly || s.cfg.NoText {
				http.Error(w, "text synchronization is disabled on this device", http.StatusBadRequest)
				return
			}
			kind = clipboard.KindText
		}
	}

	// Apply inbound item to local OS clipboard
	item := &clipboard.Item{
		Kind: kind,
		Data: data,
	}
	if err := s.eng.ApplyInbound(item, computedSha); err != nil {
		slog.Error("server: failed to apply inbound clipboard item", "err", err)
		http.Error(w, "failed to write item to clipboard", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// recordPeerActivity updates LastSeen and LastAddress in the trusted store if TLS client cert is present.
func (s *Server) recordPeerActivity(r *http.Request) {
	if r.TLS == nil || s.store == nil {
		return
	}
	fp := PeerFingerprint(r.TLS)
	if fp != "" {
		_ = s.store.UpdateLastSeen(fp, r.RemoteAddr)
	}
}
