package test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/store"
)

func TestRetention_EnsureDir(t *testing.T) {
	tempDir := t.TempDir()
	rm := store.NewRetentionManager(tempDir)

	if err := rm.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir failed: %v", err)
	}

	info, err := os.Stat(rm.ReceivedDir())
	if err != nil {
		t.Fatalf("received dir does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected received path to be directory")
	}

	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0700 {
			t.Fatalf("expected permissions 0700, got %04o", perm)
		}
	}
}

func TestRetention_Archive_NamingAndFormat(t *testing.T) {
	tempDir := t.TempDir()
	rm := store.NewRetentionManager(tempDir)

	// 1. Text payload
	textPayload := []byte("hello clipboard archive")
	textHash := engine.ComputeHash(textPayload)

	savedPath, err := rm.Archive("text", textPayload, textHash)
	if err != nil {
		t.Fatalf("Archive text failed: %v", err)
	}

	filename := filepath.Base(savedPath)
	// Filename format: YYYYMMDDTHHMMSSZ_<sha8>.txt
	textRegex := regexp.MustCompile(`^\d{8}T\d{6}Z_` + textHash[:8] + `\.txt$`)
	if !textRegex.MatchString(filename) {
		t.Fatalf("filename %q does not match expected format %s", filename, textRegex.String())
	}

	readData, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("failed to read archived file: %v", err)
	}
	if !bytes.Equal(readData, textPayload) {
		t.Fatalf("archived content mismatch: got %q, want %q", string(readData), string(textPayload))
	}

	// 2. Image payload
	imgPayload := makeMockPNG(4, 4)
	imgHash := engine.ComputeHash(imgPayload)

	imgSavedPath, err := rm.Archive("image", imgPayload, imgHash)
	if err != nil {
		t.Fatalf("Archive image failed: %v", err)
	}

	imgFilename := filepath.Base(imgSavedPath)
	imgRegex := regexp.MustCompile(`^\d{8}T\d{6}Z_` + imgHash[:8] + `\.png$`)
	if !imgRegex.MatchString(imgFilename) {
		t.Fatalf("image filename %q does not match expected format %s", imgFilename, imgRegex.String())
	}
}

func TestRetention_PathTraversal_Sanitization(t *testing.T) {
	tempDir := t.TempDir()
	rm := store.NewRetentionManager(tempDir)

	// Invalid short digest
	_, err := rm.Archive("text", []byte("bad"), "abc")
	if err == nil {
		t.Fatal("expected error for short sha256 digest")
	}

	// Malicious path traversal chars in sha
	maliciousDigests := []string{
		"../../etc/passwd",
		"..\\..\\windows\\system32",
		"abcd1234/../../secret",
	}

	for _, mal := range maliciousDigests {
		_, err := rm.Archive("text", []byte("bad"), mal)
		if err == nil {
			t.Fatalf("expected error for traversal digest %q, got nil", mal)
		}
	}
}

func TestRetention_Pruning_Limit20(t *testing.T) {
	tempDir := t.TempDir()
	rm := store.NewRetentionManager(tempDir)
	if err := rm.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir failed: %v", err)
	}

	// Create 25 sequential files with staggered modification times
	now := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 25; i++ {
		filename := fmt.Sprintf("20261124T1000%02dZ_abcdef%02d.txt", i, i)
		filePath := filepath.Join(rm.ReceivedDir(), filename)
		if err := os.WriteFile(filePath, []byte(fmt.Sprintf("item %d", i)), 0600); err != nil {
			t.Fatalf("failed to create dummy file: %v", err)
		}
		// Set increasing modification times
		modTime := now.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(filePath, modTime, modTime); err != nil {
			t.Fatalf("failed to set mtime on dummy file: %v", err)
		}
	}

	// Verify 25 files exist prior to pruning
	entriesBefore, err := os.ReadDir(rm.ReceivedDir())
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}
	if len(entriesBefore) != 25 {
		t.Fatalf("expected 25 files before pruning, found %d", len(entriesBefore))
	}

	// Execute pruning
	if err := rm.Prune(); err != nil {
		t.Fatalf("Prune failed: %v", err)
	}

	// Verify exactly 20 files remain
	entriesAfter, err := os.ReadDir(rm.ReceivedDir())
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}
	if len(entriesAfter) != 20 {
		t.Fatalf("expected 20 files after pruning, found %d", len(entriesAfter))
	}

	// Verify the 5 oldest (indices 0..4) were removed and 5..24 remain
	for i := 0; i < 5; i++ {
		oldFilename := fmt.Sprintf("20261124T1000%02dZ_abcdef%02d.txt", i, i)
		oldPath := filepath.Join(rm.ReceivedDir(), oldFilename)
		if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
			t.Fatalf("expected old file %s to be pruned", oldFilename)
		}
	}

	for i := 5; i < 25; i++ {
		newFilename := fmt.Sprintf("20261124T1000%02dZ_abcdef%02d.txt", i, i)
		newPath := filepath.Join(rm.ReceivedDir(), newFilename)
		if _, err := os.Stat(newPath); err != nil {
			t.Fatalf("expected newer file %s to remain on disk: %v", newFilename, err)
		}
	}
}

func TestRetention_Server_Integration(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Defaults()
	cfg.ConfigDir = tempDir

	ident, err := identity.LoadOrGenerate(tempDir, "server-node")
	if err != nil {
		t.Fatalf("failed to load identity: %v", err)
	}
	st, err := store.New(filepath.Join(tempDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	fakeClip := clipboard.NewFake()
	eng := engine.New(&cfg, fakeClip)

	rawListener := newMemPipeListener("127.0.0.1:47850")
	server, err := transport.NewServerWithListener(&cfg, ident, st, eng, rawListener)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	rm := server.RetentionManager()
	if rm == nil {
		t.Fatal("expected server to have a RetentionManager")
	}

	// Issue upload to server handler
	textData := []byte("sync and archive message")
	shaHex := engine.ComputeHash(textData)

	req := httptest.NewRequest(http.MethodPut, "/v1/items/test-item-1", bytes.NewReader(textData))
	req.Header.Set(transport.HeaderProtoVersion, transport.ProtoVersion)
	req.Header.Set(transport.HeaderSha256, shaHex)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Wait briefly for asynchronous background archival
	var foundFile string
	for i := 0; i < 30; i++ {
		time.Sleep(30 * time.Millisecond)
		entries, err := os.ReadDir(rm.ReceivedDir())
		if err == nil && len(entries) > 0 {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".txt") && strings.Contains(entry.Name(), shaHex[:8]) {
					foundFile = entry.Name()
					break
				}
			}
		}
		if foundFile != "" {
			break
		}
	}

	if foundFile == "" {
		t.Fatal("expected item to be archived into received/ by server")
	}

	savedBytes, err := os.ReadFile(filepath.Join(rm.ReceivedDir(), foundFile))
	if err != nil {
		t.Fatalf("failed to read archived file: %v", err)
	}
	if !bytes.Equal(savedBytes, textData) {
		t.Fatalf("archived file data mismatch: got %q, want %q", string(savedBytes), string(textData))
	}
}
