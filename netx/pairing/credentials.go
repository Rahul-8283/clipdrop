package pairing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Standard credential errors.
var (
	ErrInvalidCredentials = errors.New("pairing: device credentials must contain non-empty ID and Name")
	ErrInvalidKeySize     = errors.New("pairing: key must be 32 bytes for AES-256")
	ErrCiphertextTooShort = errors.New("pairing: ciphertext too short to contain nonce")
	ErrDecryptionFailed   = errors.New("pairing: failed to decrypt credentials (authentication tag mismatch)")
)

// Credentials contains device metadata exchanged between peers once PAKE key agreement succeeds.
type Credentials struct {
	DeviceID string `json:"device_id"` // Lowercase hex SHA-256 fingerprint
	Name     string `json:"name"`      // Device hostname
	OS       string `json:"os"`        // Operating system ("darwin", "windows", "linux")
}

// EncryptCredentials serializes credentials to JSON and encrypts them using AES-256-GCM
// with the derived 32-byte symmetric key and a random 12-byte nonce.
func EncryptCredentials(creds *Credentials, key []byte) ([]byte, error) {
	if creds == nil || strings.TrimSpace(creds.DeviceID) == "" || strings.TrimSpace(creds.Name) == "" {
		return nil, ErrInvalidCredentials
	}
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	normCreds := *creds
	normCreds.DeviceID = strings.ToLower(strings.TrimSpace(normCreds.DeviceID))
	normCreds.Name = strings.TrimSpace(normCreds.Name)

	plaintext, err := json.Marshal(normCreds)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to marshal credentials: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to initialize GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("pairing: failed to generate random nonce: %w", err)
	}

	// Seal appends ciphertext + authentication tag to the nonce prefix
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, nil
}

// DecryptCredentials extracts the nonce, decrypts the ciphertext using AES-256-GCM,
// verifies message authenticity, and deserializes the Credentials structure.
func DecryptCredentials(ciphertext []byte, key []byte) (*Credentials, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to initialize GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrCiphertextTooShort
	}

	nonce := ciphertext[:gcm.NonceSize()]
	actualCiphertext := ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	var creds Credentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("pairing: failed to unmarshal decrypted credentials: %w", err)
	}

	creds.DeviceID = strings.ToLower(strings.TrimSpace(creds.DeviceID))
	creds.Name = strings.TrimSpace(creds.Name)

	if creds.DeviceID == "" || creds.Name == "" {
		return nil, ErrInvalidCredentials
	}

	return &creds, nil
}
