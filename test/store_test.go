package test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/store"
)

func TestStore_NewEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	st, err := store.New(filePath)
	if err != nil {
		t.Fatalf("unexpected error creating new store: %v", err)
	}

	if len(st.List()) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(st.List()))
	}
	if st.IsTrusted("nonexistent") {
		t.Fatal("expected IsTrusted to return false for nonexistent device")
	}
}

func TestStore_Add_Get_IsTrusted(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	st, err := store.New(filePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dev := &store.Device{
		ID:          "A1B2C3D4E5F60102030405060708090A0B0C0D0E0F1011121314151617181920",
		Name:        "laptop-mac",
		OS:          "darwin",
		PairedAt:    time.Now().Add(-1 * time.Hour),
		LastSeen:    time.Now().Add(-10 * time.Minute),
		LastAddress: "192.168.1.50:47820",
	}

	if err := st.Add(dev); err != nil {
		t.Fatalf("failed to add device: %v", err)
	}

	// Verify IsTrusted works case-insensitively
	lowerID := "a1b2c3d4e5f60102030405060708090a0b0c0d0e0f1011121314151617181920"
	upperID := "A1B2C3D4E5F60102030405060708090A0B0C0D0E0F1011121314151617181920"

	if !st.IsTrusted(lowerID) {
		t.Fatal("expected lowerID to be trusted")
	}
	if !st.IsTrusted(upperID) {
		t.Fatal("expected upperID to be trusted via case normalization")
	}
	if st.IsTrusted("unknown-fingerprint") {
		t.Fatal("expected unknown fingerprint to not be trusted")
	}

	// Verify Get
	retrieved, ok := st.Get(lowerID)
	if !ok || retrieved == nil {
		t.Fatal("failed to Get device")
	}
	if retrieved.Name != dev.Name || retrieved.OS != dev.OS || retrieved.LastAddress != dev.LastAddress {
		t.Fatalf("device properties mismatch: %+v vs %+v", retrieved, dev)
	}

	// Verify defensive copy (modifying retrieved does not mutate store)
	retrieved.Name = "mutated-name"
	retrieved2, _ := st.Get(lowerID)
	if retrieved2.Name == "mutated-name" {
		t.Fatal("Get leaked mutable reference to internal map value")
	}

	// Verify file permissions on Unix
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("failed to stat file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected permissions 0600, got %04o", info.Mode().Perm())
		}
	}
}

func TestStore_UpdateLastSeen(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	st, err := store.New(filePath)
	if err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	origPaired := time.Now().Add(-2 * time.Hour)
	origSeen := time.Now().Add(-1 * time.Hour)

	dev := &store.Device{
		ID:          "device-1234",
		Name:        "remote-pc",
		OS:          "windows",
		PairedAt:    origPaired,
		LastSeen:    origSeen,
		LastAddress: "192.168.1.10:47820",
	}
	if err := st.Add(dev); err != nil {
		t.Fatalf("failed to add device: %v", err)
	}

	// Update last seen
	time.Sleep(10 * time.Millisecond)
	newAddr := "192.168.1.99:47820"
	if err := st.UpdateLastSeen("device-1234", newAddr); err != nil {
		t.Fatalf("failed to update last seen: %v", err)
	}

	updated, ok := st.Get("device-1234")
	if !ok {
		t.Fatal("device not found after update")
	}
	if updated.LastAddress != newAddr {
		t.Fatalf("got address %s, want %s", updated.LastAddress, newAddr)
	}
	if !updated.LastSeen.After(origSeen) {
		t.Fatalf("expected LastSeen to advance, got %v <= %v", updated.LastSeen, origSeen)
	}

	// Non-existent device error
	if err := st.UpdateLastSeen("missing-device", "1.2.3.4"); !errors.Is(err, store.ErrDeviceNotFound) {
		t.Fatalf("expected ErrDeviceNotFound, got %v", err)
	}
}

func TestStore_Remove(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	st, err := store.New(filePath)
	if err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	dev := &store.Device{
		ID:   "device-to-remove",
		Name: "untrusted-soon",
		OS:   "linux",
	}
	if err := st.Add(dev); err != nil {
		t.Fatalf("failed to add device: %v", err)
	}

	if !st.IsTrusted("device-to-remove") {
		t.Fatal("device should be trusted initially")
	}

	// Remove device
	if err := st.Remove("device-to-remove"); err != nil {
		t.Fatalf("failed to remove device: %v", err)
	}

	if st.IsTrusted("device-to-remove") {
		t.Fatal("device should not be trusted after Remove")
	}
	if _, ok := st.Get("device-to-remove"); ok {
		t.Fatal("device should not be found by Get after Remove")
	}

	// Second remove should return ErrDeviceNotFound
	if err := st.Remove("device-to-remove"); !errors.Is(err, store.ErrDeviceNotFound) {
		t.Fatalf("expected ErrDeviceNotFound on duplicate removal, got %v", err)
	}
}

func TestStore_List_Sorted(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	st, err := store.New(filePath)
	if err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	baseTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	dev1 := &store.Device{ID: "dev-1", Name: "first", PairedAt: baseTime}
	dev2 := &store.Device{ID: "dev-2", Name: "second", PairedAt: baseTime.Add(1 * time.Hour)}
	dev3 := &store.Device{ID: "dev-3", Name: "third", PairedAt: baseTime.Add(2 * time.Hour)}

	// Add out of order
	_ = st.Add(dev3)
	_ = st.Add(dev1)
	_ = st.Add(dev2)

	list := st.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(list))
	}
	if list[0].ID != "dev-1" || list[1].ID != "dev-2" || list[2].ID != "dev-3" {
		t.Fatalf("unexpected order: %s, %s, %s", list[0].ID, list[1].ID, list[2].ID)
	}
}

func TestStore_Persistence_And_Reload(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	st1, err := store.New(filePath)
	if err != nil {
		t.Fatalf("failed to create store 1: %v", err)
	}

	dev1 := &store.Device{ID: "id-1", Name: "node-1", OS: "darwin"}
	dev2 := &store.Device{ID: "id-2", Name: "node-2", OS: "windows"}

	if err := st1.Add(dev1); err != nil {
		t.Fatalf("failed to add dev1: %v", err)
	}
	if err := st1.Add(dev2); err != nil {
		t.Fatalf("failed to add dev2: %v", err)
	}

	// Reload from the same file into a new Store instance
	st2, err := store.New(filePath)
	if err != nil {
		t.Fatalf("failed to create store 2: %v", err)
	}

	if len(st2.List()) != 2 {
		t.Fatalf("expected 2 devices loaded, got %d", len(st2.List()))
	}
	if !st2.IsTrusted("id-1") || !st2.IsTrusted("id-2") {
		t.Fatal("expected both devices to be trusted in reloaded store")
	}

	// Verify temp file does not remain
	tmpFilePath := filePath + ".tmp"
	if _, err := os.Stat(tmpFilePath); !os.IsNotExist(err) {
		t.Fatal("expected temporary file to be removed after commit")
	}
}

func TestStore_ArrayFormatCompat(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	// Pre-populate with array format
	devices := []*store.Device{
		{ID: "arr-1", Name: "array-node-1", OS: "linux"},
		{ID: "arr-2", Name: "array-node-2", OS: "darwin"},
	}
	raw, err := json.Marshal(devices)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(filePath, raw, 0600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	st, err := store.New(filePath)
	if err != nil {
		t.Fatalf("failed to load array format store: %v", err)
	}

	if !st.IsTrusted("arr-1") || !st.IsTrusted("arr-2") {
		t.Fatal("expected array format entries to be loaded")
	}
}

func TestStore_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	if err := os.WriteFile(filePath, []byte("NOT_VALID_JSON{"), 0600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if _, err := store.New(filePath); err == nil {
		t.Fatal("expected error on corrupt JSON file, got nil")
	}
}

func TestStore_Concurrency_Race(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trusted_devices.json")

	st, err := store.New(filePath)
	if err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	var wg sync.WaitGroup
	workers := 10

	for i := 0; i < workers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			devID := filepath.Base(filePath) + string(rune('a'+workerID))

			// Add
			_ = st.Add(&store.Device{
				ID:   devID,
				Name: "worker-dev",
				OS:   "darwin",
			})

			// Read
			_ = st.IsTrusted(devID)
			_, _ = st.Get(devID)
			_ = st.List()

			// Update
			_ = st.UpdateLastSeen(devID, "127.0.0.1:47820")

			// More reads
			_ = st.IsTrusted(devID)
		}()
	}

	wg.Wait()
}
