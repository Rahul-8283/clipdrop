// Package store manages trusted peer device records and provides atomic,
// thread-safe persistence for the trusted_devices.json state file.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Standard store errors.
var (
	ErrDeviceNotFound = errors.New("store: device not found")
	ErrInvalidDevice  = errors.New("store: device or device ID cannot be empty")
)

// Device represents a trusted peer device authorized to synchronize clipboard events.
type Device struct {
	ID          string    `json:"id"`           // Lowercase hex SHA-256 fingerprint of peer leaf certificate
	Name        string    `json:"name"`         // Hostname / device display name
	OS          string    `json:"os"`           // Operating system ("darwin", "windows", "linux")
	PairedAt    time.Time `json:"paired_at"`    // Timestamp when mutual pairing was established
	LastSeen    time.Time `json:"last_seen"`    // Timestamp of most recent communication or ping
	LastAddress string    `json:"last_address"` // Most recent IP address and port (e.g. "192.168.1.50:47820")
}

// Store provides thread-safe access and atomic persistence for trusted devices.
type Store struct {
	mu       sync.RWMutex
	filePath string
	devices  map[string]*Device
}

// New loads an existing trusted_devices.json file from filePath, or initializes
// an empty store if the file does not yet exist.
func New(filePath string) (*Store, error) {
	s := &Store{
		filePath: filePath,
		devices:  make(map[string]*Device),
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("store: failed to read trusted devices: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return s, nil
	}

	// Support both map {"<id>": Device} and array [Device, ...] formats
	if trimmed[0] == '[' {
		var list []*Device
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("store: failed to parse JSON: %w", err)
		}
		for _, d := range list {
			if d != nil && d.ID != "" {
				normID := strings.ToLower(strings.TrimSpace(d.ID))
				d.ID = normID
				s.devices[normID] = d
			}
		}
	} else {
		if err := json.Unmarshal(trimmed, &s.devices); err != nil {
			return nil, fmt.Errorf("store: failed to parse JSON: %w", err)
		}
		// Clean up nil entries or non-normalized IDs
		clean := make(map[string]*Device, len(s.devices))
		for k, v := range s.devices {
			if v != nil && v.ID != "" {
				normID := strings.ToLower(strings.TrimSpace(v.ID))
				v.ID = normID
				clean[normID] = v
			} else if v != nil && k != "" {
				normID := strings.ToLower(strings.TrimSpace(k))
				v.ID = normID
				clean[normID] = v
			}
		}
		s.devices = clean
	}

	return s, nil
}

// IsTrusted performs a fast, thread-safe lookup to verify if the certificate
// fingerprint matches a trusted peer. Used during mTLS handshake verification.
func (s *Store) IsTrusted(deviceID string) bool {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if normID == "" {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.devices[normID]
	return ok
}

// Get retrieves metadata for a specific trusted device by its fingerprint.
// Returns a defensive copy to prevent caller mutation without locking.
func (s *Store) Get(deviceID string) (*Device, bool) {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if normID == "" {
		return nil, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	dev, ok := s.devices[normID]
	if !ok {
		return nil, false
	}

	devCopy := *dev
	return &devCopy, true
}

// Add inserts or updates a trusted peer record and flushes state atomically to disk.
func (s *Store) Add(device *Device) error {
	if device == nil || strings.TrimSpace(device.ID) == "" {
		return ErrInvalidDevice
	}

	normID := strings.ToLower(strings.TrimSpace(device.ID))
	devCopy := *device
	devCopy.ID = normID

	now := time.Now()
	if devCopy.PairedAt.IsZero() {
		devCopy.PairedAt = now
	}
	if devCopy.LastSeen.IsZero() {
		devCopy.LastSeen = now
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.devices[normID] = &devCopy
	return s.saveLocked()
}

// UpdateLastSeen refreshes the LastSeen timestamp and optionally the LastAddress
// for a trusted device, then flushes state to disk.
func (s *Store) UpdateLastSeen(deviceID, address string) error {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if normID == "" {
		return ErrInvalidDevice
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dev, ok := s.devices[normID]
	if !ok {
		return ErrDeviceNotFound
	}

	dev.LastSeen = time.Now()
	if address != "" {
		dev.LastAddress = address
	}

	return s.saveLocked()
}

// Remove revokes trust for a peer device by ID and flushes state atomically to disk.
func (s *Store) Remove(deviceID string) error {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if normID == "" {
		return ErrInvalidDevice
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.devices[normID]; !ok {
		return ErrDeviceNotFound
	}

	delete(s.devices, normID)
	return s.saveLocked()
}

// List returns all currently trusted devices sorted ascending by pairing date.
func (s *Store) List() []*Device {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*Device, 0, len(s.devices))
	for _, dev := range s.devices {
		devCopy := *dev
		list = append(list, &devCopy)
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].PairedAt.Equal(list[j].PairedAt) {
			return list[i].ID < list[j].ID
		}
		return list[i].PairedAt.Before(list[j].PairedAt)
	})

	return list
}

// saveLocked writes the in-memory devices index to a temporary sibling file,
// synchronizes it to persistent storage, and atomically renames it over filePath.
// Must be called with s.mu held.
func (s *Store) saveLocked() error {
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("store: failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(s.devices, "", "  ")
	if err != nil {
		return fmt.Errorf("store: failed to marshal devices: %w", err)
	}
	data = append(data, '\n')

	tmpPath := s.filePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("store: failed to create temp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store: failed to write temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store: failed to sync temp file: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store: failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, s.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store: failed to commit trusted devices file: %w", err)
	}

	return nil
}
