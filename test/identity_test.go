package test

import (
	"crypto/elliptic"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/identity"
)

func TestIdentity_Generate(t *testing.T) {
	ident, err := identity.Generate("test-macbook")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if ident.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if ident.PrivateKey.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve, got %v", ident.PrivateKey.Curve)
	}
	if ident.Certificate == nil {
		t.Fatal("certificate is nil")
	}
	if ident.Certificate.Subject.CommonName != "test-macbook" {
		t.Fatalf("expected CommonName 'test-macbook', got %q", ident.Certificate.Subject.CommonName)
	}

	// 10-year validity check
	validityDuration := ident.Certificate.NotAfter.Sub(ident.Certificate.NotBefore)
	expectedApprox := 10 * 365 * 24 * time.Hour
	if validityDuration < expectedApprox-24*time.Hour {
		t.Fatalf("certificate validity too short: %v", validityDuration)
	}

	// Device ID check
	if len(ident.DeviceID) != 64 {
		t.Fatalf("expected 64-char hex device ID, got %q (len: %d)", ident.DeviceID, len(ident.DeviceID))
	}
}

func TestIdentity_LoadOrGenerate_NewAndReload(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. First run: generate and save
	ident1, err := identity.LoadOrGenerate(tmpDir, "test-pc")
	if err != nil {
		t.Fatalf("first LoadOrGenerate failed: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "key.pem")
	certPath := filepath.Join(tmpDir, "cert.pem")

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key.pem not found: %v", err)
	}
	if runtime.GOOS != "windows" {
		if keyInfo.Mode().Perm() != 0600 {
			t.Fatalf("key.pem permissions %04o, want 0600", keyInfo.Mode().Perm())
		}
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert.pem not found: %v", err)
	}

	// 2. Second run: reload existing identity
	ident2, err := identity.LoadOrGenerate(tmpDir, "test-pc")
	if err != nil {
		t.Fatalf("second LoadOrGenerate failed: %v", err)
	}

	if ident2.DeviceID != ident1.DeviceID {
		t.Fatalf("reloaded DeviceID mismatch: got %s, want %s", ident2.DeviceID, ident1.DeviceID)
	}
	if !ident1.PrivateKey.Equal(ident2.PrivateKey) {
		t.Fatal("reloaded private key does not match original")
	}
}

func TestIdentity_InsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping Unix permission test on Windows")
	}

	tmpDir := t.TempDir()

	_, err := identity.LoadOrGenerate(tmpDir, "test-host")
	if err != nil {
		t.Fatalf("initial generation failed: %v", err)
	}

	// Make key.pem world-readable (0644)
	keyPath := filepath.Join(tmpDir, "key.pem")
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	// Loading should fail due to insecure permissions
	_, err = identity.LoadOrGenerate(tmpDir, "test-host")
	if !errors.Is(err, identity.ErrInsecurePermissions) {
		t.Fatalf("expected ErrInsecurePermissions, got: %v", err)
	}
}
