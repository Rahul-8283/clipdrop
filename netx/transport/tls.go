package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/store"
)

// TLS errors for peer authentication.
var (
	ErrUntrustedPeer = errors.New("transport: untrusted peer certificate")
	ErrNoPeerCert    = errors.New("transport: no peer certificate presented")
)

// verifyPeerCertificate inspects the leaf certificate presented by the peer,
// calculates its SHA-256 fingerprint, and validates it against the trusted devices store.
func verifyPeerCertificate(rawCerts [][]byte, st *store.Store) error {
	if len(rawCerts) == 0 {
		return ErrNoPeerCert
	}

	leafRaw := rawCerts[0]
	digest := sha256.Sum256(leafRaw)
	fingerprint := hex.EncodeToString(digest[:])

	if st == nil || !st.IsTrusted(fingerprint) {
		slog.Warn("transport: rejected connection from untrusted peer",
			"fingerprint", fingerprint,
		)
		return fmt.Errorf("%w: fingerprint=%s", ErrUntrustedPeer, fingerprint)
	}

	return nil
}

// ServerTLSConfig creates a strictly pinned mTLS 1.3 server configuration.
// It requires connecting clients to present an X.509 client certificate
// whose SHA-256 fingerprint must be explicitly registered in the local store.
func ServerTLSConfig(ident *identity.Identity, st *store.Store) *tls.Config {
	var certs []tls.Certificate
	if ident != nil && len(ident.TLSCert.Certificate) > 0 {
		certs = []tls.Certificate{ident.TLSCert}
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: certs,
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerCertificate(rawCerts, st)
		},
	}
}

// ClientTLSConfig creates a strictly pinned mTLS 1.3 client configuration.
// It presents the local identity certificate to the server and verifies
// that the remote server's certificate is present in the local trusted store.
func ClientTLSConfig(ident *identity.Identity, st *store.Store) *tls.Config {
	var certs []tls.Certificate
	if ident != nil && len(ident.TLSCert.Certificate) > 0 {
		certs = []tls.Certificate{ident.TLSCert}
	}

	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		Certificates:       certs,
		InsecureSkipVerify: true, // Bypass public CA verification in favor of pinned store verification
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerCertificate(rawCerts, st)
		},
	}
}

// PeerFingerprint extracts the canonical lowercase hexadecimal SHA-256
// fingerprint from a connection state's verified peer certificates.
func PeerFingerprint(cs *tls.ConnectionState) string {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return ""
	}
	return identity.Fingerprint(cs.PeerCertificates[0])
}
