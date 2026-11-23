package test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

// roundTripperFunc converts a function into an http.RoundTripper for in-memory testing.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// handlerTransport routes HTTP requests directly to an http.Handler without TCP sockets.
func handlerTransport(h http.Handler) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		res := rec.Result()
		res.Request = req
		return res, nil
	})
}

func TestClient_Constructor(t *testing.T) {
	tmpDir := t.TempDir()
	ident, err := identity.LoadOrGenerate(tmpDir, "node-client")
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}
	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	client := transport.NewClient(ident, st)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClient_Ping_Success(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/ping" {
			http.Error(w, "bad route", http.StatusNotFound)
			return
		}
		if r.Header.Get(transport.HeaderProtoVersion) != transport.ProtoVersion {
			http.Error(w, "bad proto version", http.StatusBadRequest)
			return
		}

		resp := transport.PingResponse{
			DeviceName:      "remote-host",
			ProtocolVersion: 1,
			CurrentTime:     time.Now().UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	httpClient := &http.Client{Transport: handlerTransport(handler)}
	client := transport.NewClientWithHTTPClient(httpClient)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.Ping(ctx, "192.168.1.50:47820")
	if err != nil {
		t.Fatalf("unexpected ping error: %v", err)
	}
	if resp.DeviceName != "remote-host" {
		t.Fatalf("got device name %s, want remote-host", resp.DeviceName)
	}
	if resp.ProtocolVersion != 1 {
		t.Fatalf("got proto version %d, want 1", resp.ProtocolVersion)
	}
}

func TestClient_Ping_ErrorStatus(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "peer is busy", http.StatusServiceUnavailable)
	})

	httpClient := &http.Client{Transport: handlerTransport(handler)}
	client := transport.NewClientWithHTTPClient(httpClient)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.Ping(ctx, "192.168.1.50:47820")
	if err == nil {
		t.Fatal("expected error on non-200 status, got nil")
	}
	if !errors.Is(err, transport.ErrUnexpectedStatus) {
		t.Fatalf("expected ErrUnexpectedStatus, got %v", err)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error should include HTTP status 503, got %v", err)
	}
}

func TestClient_Offer_SuccessAndSkip(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/offer" {
			http.Error(w, "bad route", http.StatusNotFound)
			return
		}
		if r.Header.Get(transport.HeaderProtoVersion) != transport.ProtoVersion {
			http.Error(w, "missing proto header", http.StatusBadRequest)
			return
		}

		var req transport.OfferRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		var resp transport.OfferResponse
		if req.Sha256 == "known-dup" {
			resp = transport.OfferResponse{Action: transport.ActionSkip, Reason: transport.ReasonDuplicate}
		} else {
			resp = transport.OfferResponse{Action: transport.ActionSend}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	httpClient := &http.Client{Transport: handlerTransport(handler)}
	client := transport.NewClientWithHTTPClient(httpClient)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Offer accepted (send)
	req := &transport.OfferRequest{
		ID:     "transfer-1",
		Kind:   "text",
		Size:   128,
		Sha256: "unique-hash",
		Mime:   "text/plain; charset=utf-8",
	}
	resp, err := client.Offer(ctx, "192.168.1.50:47820", req)
	if err != nil {
		t.Fatalf("unexpected offer error: %v", err)
	}
	if resp.Action != transport.ActionSend {
		t.Fatalf("expected send, got %s", resp.Action)
	}

	// 2. Offer skipped (duplicate)
	reqDup := &transport.OfferRequest{
		ID:     "transfer-2",
		Kind:   "text",
		Size:   128,
		Sha256: "known-dup",
		Mime:   "text/plain; charset=utf-8",
	}
	respDup, err := client.Offer(ctx, "192.168.1.50:47820", reqDup)
	if err != nil {
		t.Fatalf("unexpected offer error: %v", err)
	}
	if respDup.Action != transport.ActionSkip || respDup.Reason != transport.ReasonDuplicate {
		t.Fatalf("expected skip duplicate, got %+v", respDup)
	}
}

func TestClient_Upload_SuccessAndFailure(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/v1/items/") {
			http.Error(w, "bad route", http.StatusNotFound)
			return
		}
		if r.Header.Get(transport.HeaderProtoVersion) != transport.ProtoVersion {
			http.Error(w, "bad proto", http.StatusBadRequest)
			return
		}
		if r.Header.Get(transport.HeaderSha256) == "bad-hash" {
			http.Error(w, "hash mismatch", http.StatusUnprocessableEntity)
			return
		}

		body, _ := io.ReadAll(r.Body)
		if string(body) != "clip-data" {
			http.Error(w, "wrong payload", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	httpClient := &http.Client{Transport: handlerTransport(handler)}
	client := transport.NewClientWithHTTPClient(httpClient)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Successful upload
	err := client.Upload(ctx, "192.168.1.50:47820", "item-1", []byte("clip-data"),
		clipboard.KindText, "text/plain; charset=utf-8", "good-hash")
	if err != nil {
		t.Fatalf("unexpected upload error: %v", err)
	}

	// 2. Upload rejected by server (422)
	err = client.Upload(ctx, "192.168.1.50:47820", "item-2", []byte("clip-data"),
		clipboard.KindText, "text/plain; charset=utf-8", "bad-hash")
	if err == nil {
		t.Fatal("expected upload error for bad hash, got nil")
	}
	if !errors.Is(err, transport.ErrUnexpectedStatus) {
		t.Fatalf("expected ErrUnexpectedStatus, got %v", err)
	}
	if !strings.Contains(err.Error(), "422") {
		t.Fatalf("expected error to mention 422, got %v", err)
	}
}
