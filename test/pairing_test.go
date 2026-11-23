package test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Rahul-8283/clipdrop/netx/pairing"
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
