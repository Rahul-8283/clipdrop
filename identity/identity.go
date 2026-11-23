// Package identity handles local cryptographic key generation, self-signed
// X.509 certificate creation, device fingerprinting, and secure persistence.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Standard identity errors.
var (
	ErrInsecurePermissions = errors.New("identity: private key file permissions are too open (must be 0600)")
	ErrCorruptCredentials  = errors.New("identity: corrupted key or certificate file")
)

// Identity represents the device's cryptographic identity used for mTLS 1.3 authentication.
type Identity struct {
	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate
	DeviceID    string
	TLSCert     tls.Certificate
}

// Fingerprint calculates the canonical SHA-256 fingerprint of a certificate's raw DER bytes,
// formatted as a lowercase 64-character hexadecimal string.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// LoadOrGenerate loads existing ECDSA credentials from configDir, or generates a new
// NIST P-256 keypair and self-signed X.509 certificate if they do not exist.
func LoadOrGenerate(configDir string, hostname string) (*Identity, error) {
	keyPath := filepath.Join(configDir, "key.pem")
	certPath := filepath.Join(configDir, "cert.pem")

	// If credentials already exist, load and validate them
	if fileExists(keyPath) && fileExists(certPath) {
		return load(keyPath, certPath)
	}

	// Otherwise generate a fresh identity and persist it
	return generateAndSave(keyPath, certPath, hostname)
}

// Generate creates an ephemeral in-memory Identity without saving to disk.
func Generate(hostname string) (*Identity, error) {
	// 1. Generate ECDSA P-256 private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating P-256 key: %w", err)
	}

	// 2. Generate random 128-bit serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating certificate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: now.Add(-1 * time.Minute), // cushion against clock skew
		NotAfter:  now.AddDate(10, 0, 0),     // 10-year validity
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{hostname, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}

	// 3. Create self-signed certificate DER
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("creating self-signed certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing created certificate: %w", err)
	}

	deviceID := Fingerprint(parsedCert)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
		Leaf:        parsedCert,
	}

	return &Identity{
		PrivateKey:  privKey,
		Certificate: parsedCert,
		DeviceID:    deviceID,
		TLSCert:     tlsCert,
	}, nil
}

func generateAndSave(keyPath, certPath, hostname string) (*Identity, error) {
	ident, err := Generate(hostname)
	if err != nil {
		return nil, err
	}

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(ident.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ident.Certificate.Raw,
	})

	// Save to disk with strict 0600 permissions
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing key.pem: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing cert.pem: %w", err)
	}

	return ident, nil
}

func load(keyPath, certPath string) (*Identity, error) {
	// Verify strict permissions on Unix systems
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil {
			return nil, fmt.Errorf("stat key file: %w", err)
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("%w: %s has mode %04o, want 0600", ErrInsecurePermissions, keyPath, info.Mode().Perm())
		}
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading key.pem: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading cert.pem: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptCredentials, err)
	}

	parsedCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing loaded certificate: %w", err)
	}
	tlsCert.Leaf = parsedCert

	privKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: private key is not ECDSA", ErrCorruptCredentials)
	}

	return &Identity{
		PrivateKey:  privKey,
		Certificate: parsedCert,
		DeviceID:    Fingerprint(parsedCert),
		TLSCert:     tlsCert,
	}, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
