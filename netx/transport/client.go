package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

// Standard client errors.
var (
	ErrUnexpectedStatus = errors.New("transport: unexpected HTTP response status")
)

// Client provides an HTTP client with pinned mTLS 1.3 authentication
// for communicating with remote Clipdrop peers.
type Client struct {
	httpClient *http.Client
}

// NewClient constructs an mTLS-authenticated Client using the local device identity
// and validating remote peers against the trusted devices store.
func NewClient(ident *identity.Identity, st *store.Store) *Client {
	tlsConfig := ClientTLSConfig(ident, st)

	tr := &http.Transport{
		TLSClientConfig:       tlsConfig,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ResponseHeaderTimeout: 3 * time.Second,
		ForceAttemptHTTP2:     false,
	}

	httpClient := &http.Client{
		Transport: tr,
	}

	return &Client{
		httpClient: httpClient,
	}
}

// NewClientWithHTTPClient constructs a Client wrapping an arbitrary http.Client (e.g. for testing).
func NewClientWithHTTPClient(httpClient *http.Client) *Client {
	return &Client{
		httpClient: httpClient,
	}
}

// Ping sends a lightweight health check to GET /v1/ping on the remote peer.
func (c *Client) Ping(ctx context.Context, addr string) (*PingResponse, error) {
	urlStr := formatURL(addr, "/v1/ping")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("transport: failed to create ping request: %w", err)
	}

	req.Header.Set(HeaderProtoVersion, ProtoVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transport: ping failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%w: status %d (%s)", ErrUnexpectedStatus, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var pingResp PingResponse
	if err := json.NewDecoder(resp.Body).Decode(&pingResp); err != nil {
		return nil, fmt.Errorf("transport: failed to decode ping response: %w", err)
	}

	return &pingResp, nil
}

// Offer solicits transfer approval from the remote peer at POST /v1/offer before sending payload bytes.
func (c *Client) Offer(ctx context.Context, addr string, offerReq *OfferRequest) (*OfferResponse, error) {
	if offerReq == nil {
		return nil, errors.New("transport: offer request cannot be nil")
	}

	payload, err := json.Marshal(offerReq)
	if err != nil {
		return nil, fmt.Errorf("transport: failed to marshal offer request: %w", err)
	}

	urlStr := formatURL(addr, "/v1/offer")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("transport: failed to create offer request: %w", err)
	}

	req.Header.Set(HeaderProtoVersion, ProtoVersion)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transport: offer request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%w: status %d (%s)", ErrUnexpectedStatus, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var offerResp OfferResponse
	if err := json.NewDecoder(resp.Body).Decode(&offerResp); err != nil {
		return nil, fmt.Errorf("transport: failed to decode offer response: %w", err)
	}

	return &offerResp, nil
}

// Upload streams clipboard item payload bytes to PUT /v1/items/{id} on the remote peer.
func (c *Client) Upload(ctx context.Context, addr string, id string, data []byte, kind clipboard.ItemKind, mime string, hash string) error {
	uploadCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if mime == "" {
		if kind == clipboard.KindImage {
			mime = "image/png"
		} else {
			mime = "text/plain; charset=utf-8"
		}
	}

	urlStr := formatURL(addr, fmt.Sprintf("/v1/items/%s", id))
	req, err := http.NewRequestWithContext(uploadCtx, http.MethodPut, urlStr, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("transport: failed to create upload request: %w", err)
	}

	req.Header.Set(HeaderProtoVersion, ProtoVersion)
	req.Header.Set(HeaderSha256, hash)
	req.Header.Set("Content-Type", mime)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("transport: upload failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%w: status %d (%s)", ErrUnexpectedStatus, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return nil
}

// formatURL normalizes host:port into a full HTTPS URL with the requested path.
func formatURL(addr, path string) string {
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimRight(addr, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("https://%s%s", addr, path)
}
