package pairing

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/store"
)

// Join executes the client-side PAKE pairing ceremony against a target host address.
func Join(ctx context.Context, hostAddr string, code string, ident *identity.Identity, st *store.Store) (*store.Device, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	return JoinWithHTTPClient(ctx, hostAddr, code, ident, st, client)
}

// JoinWithHTTPClient executes the client-side pairing ceremony using an injected http.Client.
func JoinWithHTTPClient(ctx context.Context, hostAddr string, code string, ident *identity.Identity, st *store.Store, client *http.Client) (*store.Device, error) {
	if ident == nil || st == nil || client == nil {
		return nil, errors.New("pairing: identity, store, and client are required")
	}

	trimmedAddr := strings.TrimSpace(hostAddr)
	if trimmedAddr == "" {
		return nil, errors.New("pairing: host address cannot be empty")
	}

	normCode := NormalizeCode(code)
	if normCode == "" {
		return nil, ErrInvalidCode
	}

	baseURL := trimmedAddr
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	// Step 1: GET /v1/pair/pake to retrieve host's public Point A
	reqA, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/pair/pake", nil)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to create point A request: %w", err)
	}

	respA, err := client.Do(reqA)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to connect to host: %w", err)
	}
	defer respA.Body.Close()

	if respA.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(respA.Body, 1024))
		return nil, fmt.Errorf("pairing: host returned status %d for point A: %s", respA.StatusCode, strings.TrimSpace(string(body)))
	}

	var initResp PakeInitResponse
	if err := json.NewDecoder(respA.Body).Decode(&initResp); err != nil {
		return nil, fmt.Errorf("pairing: failed to decode point A response: %w", err)
	}

	pointA, err := hex.DecodeString(initResp.PointA)
	if err != nil || len(pointA) == 0 {
		return nil, errors.New("pairing: invalid point A received from host")
	}

	// Step 2: Initialize Joiner PAKE session with Point A and derive Point B & Session Key
	session, pointB, err := InitJoiner(normCode, pointA)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to initialize joiner PAKE session: %w", err)
	}

	joinerKey, err := SessionKey(session)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to derive session key: %w", err)
	}

	// Step 3: POST /v1/pair/pake to send Point B to host
	exchangeReq := PakeExchangeRequest{
		PointB: hex.EncodeToString(pointB),
	}
	exchangeJSON, err := json.Marshal(exchangeReq)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to marshal point B: %w", err)
	}

	reqB, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/pair/pake", bytes.NewReader(exchangeJSON))
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to create point B request: %w", err)
	}
	reqB.Header.Set("Content-Type", "application/json")

	respB, err := client.Do(reqB)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to send point B: %w", err)
	}
	defer respB.Body.Close()

	if respB.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(respB.Body, 1024))
		return nil, fmt.Errorf("pairing: host rejected point B with status %d: %s", respB.StatusCode, strings.TrimSpace(string(body)))
	}

	// Step 4: Encrypt local credentials and exchange with host
	joinerName := ident.Certificate.Subject.CommonName
	if joinerName == "" {
		joinerName = "clipdrop-joiner"
	}

	joinerCreds := &Credentials{
		DeviceID: ident.DeviceID,
		Name:     joinerName,
		OS:       runtime.GOOS,
	}

	ciphertext, err := EncryptCredentials(joinerCreds, joinerKey)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to encrypt credentials: %w", err)
	}

	payloadWrapper := EncryptedPayloadWrapper{
		Payload: hex.EncodeToString(ciphertext),
	}
	payloadJSON, err := json.Marshal(payloadWrapper)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to marshal credentials payload: %w", err)
	}

	reqEx, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/pair/exchange", bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to create exchange request: %w", err)
	}
	reqEx.Header.Set("Content-Type", "application/json")

	respEx, err := client.Do(reqEx)
	if err != nil {
		return nil, fmt.Errorf("pairing: credentials exchange request failed: %w", err)
	}
	defer respEx.Body.Close()

	if respEx.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(respEx.Body, 1024))
		return nil, fmt.Errorf("pairing: host rejected credentials exchange with status %d: %s", respEx.StatusCode, strings.TrimSpace(string(body)))
	}

	var hostRespWrapper EncryptedPayloadWrapper
	if err := json.NewDecoder(respEx.Body).Decode(&hostRespWrapper); err != nil {
		return nil, fmt.Errorf("pairing: failed to decode host exchange response: %w", err)
	}

	hostCiphertext, err := hex.DecodeString(hostRespWrapper.Payload)
	if err != nil || len(hostCiphertext) == 0 {
		return nil, errors.New("pairing: invalid encrypted payload received from host")
	}

	hostCreds, err := DecryptCredentials(hostCiphertext, joinerKey)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to decrypt host credentials (wrong code or tampered data): %w", err)
	}

	// Step 5: Save Host to local store
	now := time.Now()
	hostDevice := &store.Device{
		ID:          hostCreds.DeviceID,
		Name:        hostCreds.Name,
		OS:          hostCreds.OS,
		PairedAt:    now,
		LastSeen:    now,
		LastAddress: hostAddr,
	}

	if err := st.Add(hostDevice); err != nil {
		return nil, fmt.Errorf("pairing: failed to persist host device in store: %w", err)
	}

	return hostDevice, nil
}
