package test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/pairing"
	"github.com/Rahul-8283/clipdrop/store"
)

func TestCode_GenerateAndNormalize(t *testing.T) {
	// Generate multiple codes and assert validity
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		code, err := pairing.GenerateCode()
		if err != nil {
			t.Fatalf("failed to generate code: %v", err)
		}
		if !pairing.ValidateCodeFormat(code) {
			t.Fatalf("generated code '%s' failed format validation", code)
		}
		seen[code] = true
	}
	// Verify high randomness across 50 iterations
	if len(seen) < 48 {
		t.Fatalf("suspiciously low entropy: only %d unique codes out of 50", len(seen))
	}

	// Normalizer tests
	tests := []struct {
		input    string
		expected string
		valid    bool
	}{
		{"  8412-amber-falcon  ", "8412-amber-falcon", true},
		{"8412 amber falcon", "8412-amber-falcon", true},
		{"8412-AMBER-FALCON", "8412-amber-falcon", true},
		{"8412-amber", "8412-amber", false},
		{"invalid-format-1234", "invalid-format-1234", false},
		{"", "", false},
	}

	for _, tt := range tests {
		normalized := pairing.NormalizeCode(tt.input)
		if normalized != tt.expected {
			t.Errorf("NormalizeCode(%q) = %q; want %q", tt.input, normalized, tt.expected)
		}
		if pairing.ValidateCodeFormat(tt.input) != tt.valid {
			t.Errorf("ValidateCodeFormat(%q) = %v; want %v", tt.input, !tt.valid, tt.valid)
		}
	}
}

func TestPAKE_Handshake_Success(t *testing.T) {
	code, err := pairing.GenerateCode()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// 1. Host initializes and emits point A
	sHost, pointA, err := pairing.InitHost(code)
	if err != nil {
		t.Fatalf("InitHost failed: %v", err)
	}
	if len(pointA) == 0 {
		t.Fatal("point A must not be empty")
	}

	// 2. Joiner initializes with point A and emits point B
	sJoiner, pointB, err := pairing.InitJoiner(code, pointA)
	if err != nil {
		t.Fatalf("InitJoiner failed: %v", err)
	}
	if len(pointB) == 0 {
		t.Fatal("point B must not be empty")
	}

	// 3. Host completes handshake with point B and derives host key
	hostKey, err := pairing.CompleteHost(sHost, pointB)
	if err != nil {
		t.Fatalf("CompleteHost failed: %v", err)
	}
	if len(hostKey) != 32 {
		t.Fatalf("expected 32-byte host key, got %d", len(hostKey))
	}

	// 4. Joiner derives joiner key
	joinerKey, err := pairing.SessionKey(sJoiner)
	if err != nil {
		t.Fatalf("Joiner SessionKey failed: %v", err)
	}
	if len(joinerKey) != 32 {
		t.Fatalf("expected 32-byte joiner key, got %d", len(joinerKey))
	}

	// 5. Assert mutual derivation equality
	if !bytes.Equal(hostKey, joinerKey) {
		t.Fatal("derived session keys between Host and Joiner do not match!")
	}
}

func TestPAKE_Handshake_MismatchedCodes(t *testing.T) {
	hostCode := "1234-amber-falcon"
	wrongCode := "9999-badger-cedar"

	sHost, pointA, err := pairing.InitHost(hostCode)
	if err != nil {
		t.Fatalf("InitHost failed: %v", err)
	}

	// Joiner enters wrong code
	sJoiner, pointB, err := pairing.InitJoiner(wrongCode, pointA)
	if err != nil {
		t.Fatalf("InitJoiner failed: %v", err)
	}

	hostKey, err := pairing.CompleteHost(sHost, pointB)
	if err != nil {
		t.Fatalf("CompleteHost failed: %v", err)
	}

	joinerKey, err := pairing.SessionKey(sJoiner)
	if err != nil {
		t.Fatalf("SessionKey failed: %v", err)
	}

	// Cryptographic guarantee: keys must NOT match
	if bytes.Equal(hostKey, joinerKey) {
		t.Fatal("keys derived from different codes must not match!")
	}
}

func TestPAKE_ErrorsAndValidation(t *testing.T) {
	// Empty code on host
	if _, _, err := pairing.InitHost(""); !errors.Is(err, pairing.ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}

	// Empty code on joiner
	if _, _, err := pairing.InitJoiner("", []byte("point")); !errors.Is(err, pairing.ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}

	// Empty point A on joiner
	if _, _, err := pairing.InitJoiner("1234-amber-falcon", nil); !errors.Is(err, pairing.ErrInvalidPoint) {
		t.Fatalf("expected ErrInvalidPoint, got %v", err)
	}

	// Nil session checks
	if _, err := pairing.CompleteHost(nil, []byte("point")); !errors.Is(err, pairing.ErrNilSession) {
		t.Fatalf("expected ErrNilSession, got %v", err)
	}
	if _, err := pairing.SessionKey(nil); !errors.Is(err, pairing.ErrNilSession) {
		t.Fatalf("expected ErrNilSession, got %v", err)
	}
}

func TestCredentials_EncryptDecrypt_Success(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	creds := &pairing.Credentials{
		DeviceID: "A1B2C3D4E5F67890123456789012345678901234567890123456789012345678",
		Name:     "rahul-macbook",
		OS:       "darwin",
	}

	ciphertext, err := pairing.EncryptCredentials(creds, key)
	if err != nil {
		t.Fatalf("EncryptCredentials failed: %v", err)
	}
	if len(ciphertext) <= 12 {
		t.Fatal("ciphertext must be longer than 12-byte nonce")
	}

	decrypted, err := pairing.DecryptCredentials(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptCredentials failed: %v", err)
	}

	lowerID := "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
	if decrypted.DeviceID != lowerID {
		t.Fatalf("expected normalized device ID %s, got %s", lowerID, decrypted.DeviceID)
	}
	if decrypted.Name != "rahul-macbook" || decrypted.OS != "darwin" {
		t.Fatalf("decrypted credentials mismatch: %+v", decrypted)
	}
}

func TestCredentials_DecryptionFailed_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key1[0] = 0xAA
	key2[0] = 0xBB

	creds := &pairing.Credentials{
		DeviceID: "device-id-1234",
		Name:     "peer-node",
		OS:       "windows",
	}

	ciphertext, err := pairing.EncryptCredentials(creds, key1)
	if err != nil {
		t.Fatalf("EncryptCredentials failed: %v", err)
	}

	_, err = pairing.DecryptCredentials(ciphertext, key2)
	if err == nil {
		t.Fatal("expected decryption error with wrong key, got nil")
	}
	if !errors.Is(err, pairing.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestCredentials_DecryptionFailed_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	creds := &pairing.Credentials{
		DeviceID: "device-id-5678",
		Name:     "secure-box",
		OS:       "linux",
	}

	ciphertext, err := pairing.EncryptCredentials(creds, key)
	if err != nil {
		t.Fatalf("EncryptCredentials failed: %v", err)
	}

	// Tamper with the last byte of ciphertext (auth tag)
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = pairing.DecryptCredentials(ciphertext, key)
	if err == nil {
		t.Fatal("expected decryption error on tampered ciphertext, got nil")
	}
	if !errors.Is(err, pairing.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestCredentials_ValidationAndKeyErrors(t *testing.T) {
	validKey := make([]byte, 32)
	shortKey := make([]byte, 16)

	// Short key error
	creds := &pairing.Credentials{DeviceID: "id", Name: "name", OS: "darwin"}
	if _, err := pairing.EncryptCredentials(creds, shortKey); !errors.Is(err, pairing.ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}
	if _, err := pairing.DecryptCredentials([]byte("short-data"), shortKey); !errors.Is(err, pairing.ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}

	// Invalid credentials
	if _, err := pairing.EncryptCredentials(&pairing.Credentials{DeviceID: "", Name: "name"}, validKey); !errors.Is(err, pairing.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for empty ID, got %v", err)
	}
	if _, err := pairing.EncryptCredentials(&pairing.Credentials{DeviceID: "id", Name: ""}, validKey); !errors.Is(err, pairing.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for empty Name, got %v", err)
	}

	// Ciphertext too short
	if _, err := pairing.DecryptCredentials([]byte{1, 2, 3}, validKey); !errors.Is(err, pairing.ErrCiphertextTooShort) {
		t.Fatalf("expected ErrCiphertextTooShort, got %v", err)
	}
}

func createMemClient(listener *memPipeListener) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				cConn, sConn := net.Pipe()
				select {
				case listener.conns <- sConn:
					return cConn, nil
				case <-listener.closed:
					cConn.Close()
					sConn.Close()
					return nil, net.ErrClosed
				}
			},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}
}

func TestHostJoiner_FullCeremony_Success(t *testing.T) {
	hostDir := t.TempDir()
	hostIdent, err := identity.LoadOrGenerate(hostDir, "mac-host")
	if err != nil {
		t.Fatalf("failed to create host identity: %v", err)
	}
	hostStore, err := store.New(filepath.Join(hostDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create host store: %v", err)
	}

	joinerDir := t.TempDir()
	joinerIdent, err := identity.LoadOrGenerate(joinerDir, "win-joiner")
	if err != nil {
		t.Fatalf("failed to create joiner identity: %v", err)
	}
	joinerStore, err := store.New(filepath.Join(joinerDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create joiner store: %v", err)
	}

	code, err := pairing.GenerateCode()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	listener := newMemPipeListener("127.0.0.1:47825")
	host, err := pairing.NewHostWithListener(code, hostIdent, hostStore, listener)
	if err != nil {
		t.Fatalf("NewHostWithListener failed: %v", err)
	}

	client := createMemClient(listener)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hostDevCh := make(chan *store.Device, 1)
	hostErrCh := make(chan error, 1)
	go func() {
		dev, err := host.Serve(ctx)
		hostErrCh <- err
		hostDevCh <- dev
	}()

	joinerDev, err := pairing.JoinWithHTTPClient(ctx, "127.0.0.1:47825", code, joinerIdent, joinerStore, client)
	if err != nil {
		t.Fatalf("JoinWithHTTPClient failed: %v", err)
	}

	hostDev := <-hostDevCh
	if hostErr := <-hostErrCh; hostErr != nil {
		t.Fatalf("Host.Serve failed: %v", hostErr)
	}

	// Verify joiner received valid host credentials
	if joinerDev.ID != hostIdent.DeviceID {
		t.Errorf("joinerDev.ID = %q; want %q", joinerDev.ID, hostIdent.DeviceID)
	}
	if joinerDev.Name != "mac-host" {
		t.Errorf("joinerDev.Name = %q; want %q", joinerDev.Name, "mac-host")
	}

	// Verify host received valid joiner credentials
	if hostDev.ID != joinerIdent.DeviceID {
		t.Errorf("hostDev.ID = %q; want %q", hostDev.ID, joinerIdent.DeviceID)
	}
	if hostDev.Name != "win-joiner" {
		t.Errorf("hostDev.Name = %q; want %q", hostDev.Name, "win-joiner")
	}

	// Verify mutual trust persistence
	if !hostStore.IsTrusted(joinerIdent.DeviceID) {
		t.Errorf("joiner device not trusted in host store")
	}
	if !joinerStore.IsTrusted(hostIdent.DeviceID) {
		t.Errorf("host device not trusted in joiner store")
	}
}

func TestHostJoiner_WrongCode_BruteForceLockout(t *testing.T) {
	hostDir := t.TempDir()
	hostIdent, err := identity.LoadOrGenerate(hostDir, "mac-host")
	if err != nil {
		t.Fatalf("failed to create host identity: %v", err)
	}
	hostStore, err := store.New(filepath.Join(hostDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create host store: %v", err)
	}

	joinerDir := t.TempDir()
	joinerIdent, err := identity.LoadOrGenerate(joinerDir, "win-attacker")
	if err != nil {
		t.Fatalf("failed to create joiner identity: %v", err)
	}
	joinerStore, err := store.New(filepath.Join(joinerDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create joiner store: %v", err)
	}

	hostCode := "8412-amber-falcon"
	listener := newMemPipeListener("127.0.0.1:47826")
	host, err := pairing.NewHostWithListener(hostCode, hostIdent, hostStore, listener)
	if err != nil {
		t.Fatalf("NewHostWithListener failed: %v", err)
	}

	client := createMemClient(listener)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hostErrCh := make(chan error, 1)
	go func() {
		_, err := host.Serve(ctx)
		hostErrCh <- err
	}()

	wrongCode := "9999-badger-cedar"

	// Trigger 3 failed attempts
	for i := 1; i <= 3; i++ {
		_, err := pairing.JoinWithHTTPClient(ctx, "127.0.0.1:47826", wrongCode, joinerIdent, joinerStore, client)
		if err == nil {
			t.Fatalf("attempt %d: expected join failure with wrong code, got nil", i)
		}
	}

	// Verify host locked out and halted
	select {
	case hostErr := <-hostErrCh:
		if !errors.Is(hostErr, pairing.ErrMaxAttemptsExceeded) {
			t.Fatalf("expected ErrMaxAttemptsExceeded, got %v", hostErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("host server did not halt after 3 failed attempts")
	}

	// 4th attempt should fail immediately because host listener is closed
	_, err = pairing.JoinWithHTTPClient(ctx, "127.0.0.1:47826", wrongCode, joinerIdent, joinerStore, client)
	if err == nil {
		t.Fatal("expected failure on 4th attempt after host shutdown, got nil")
	}
}

func TestHost_SessionTimeout(t *testing.T) {
	hostDir := t.TempDir()
	hostIdent, err := identity.LoadOrGenerate(hostDir, "mac-host")
	if err != nil {
		t.Fatalf("failed to create host identity: %v", err)
	}
	hostStore, err := store.New(filepath.Join(hostDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create host store: %v", err)
	}

	listener := newMemPipeListener("127.0.0.1:47827")
	host, err := pairing.NewHostWithListener("8412-amber-falcon", hostIdent, hostStore, listener)
	if err != nil {
		t.Fatalf("NewHostWithListener failed: %v", err)
	}
	host.SetTimeout(50 * time.Millisecond)

	ctx := context.Background()
	_, err = host.Serve(ctx)
	if !errors.Is(err, pairing.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestHostJoiner_InputValidation(t *testing.T) {
	tmpDir := t.TempDir()
	ident, _ := identity.LoadOrGenerate(tmpDir, "node")
	st, _ := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	listener := newMemPipeListener("127.0.0.1:47828")
	defer listener.Close()

	// NewHostWithListener nil checks
	if _, err := pairing.NewHostWithListener("", ident, st, listener); !errors.Is(err, pairing.ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}
	if _, err := pairing.NewHostWithListener("1234-amber-falcon", nil, st, listener); err == nil {
		t.Fatal("expected error for nil identity, got nil")
	}
	if _, err := pairing.NewHostWithListener("1234-amber-falcon", ident, nil, listener); err == nil {
		t.Fatal("expected error for nil store, got nil")
	}
	if _, err := pairing.NewHostWithListener("1234-amber-falcon", ident, st, nil); err == nil {
		t.Fatal("expected error for nil listener, got nil")
	}

	// JoinWithHTTPClient nil / empty checks
	ctx := context.Background()
	client := createMemClient(listener)
	if _, err := pairing.JoinWithHTTPClient(ctx, "", "1234-amber-falcon", ident, st, client); err == nil {
		t.Fatal("expected error for empty host address, got nil")
	}
	if _, err := pairing.JoinWithHTTPClient(ctx, "localhost", "", ident, st, client); !errors.Is(err, pairing.ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}
	if _, err := pairing.JoinWithHTTPClient(ctx, "localhost", "1234-amber-falcon", nil, st, client); err == nil {
		t.Fatal("expected error for nil identity, got nil")
	}
}
