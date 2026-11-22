package engine

import "sync"

// SyncState provides thread-safe in-memory tracking of content hashes
// to enable echo loop elimination and local copy deduplication.
type SyncState struct {
	mu               sync.RWMutex
	lastReceivedHash string
	lastSentHash     string
	currentLocalHash string
}

// NewSyncState constructs an empty, initialized SyncState.
func NewSyncState() *SyncState {
	return &SyncState{}
}

// SetLastReceived records the SHA-256 hash of an item received from a remote peer.
// This must be called BEFORE applying the item to the local operating system clipboard.
func (s *SyncState) SetLastReceived(hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReceivedHash = hash
	s.currentLocalHash = hash
}

// IsLastReceived returns true if hash matches the item most recently applied from a peer.
// If true, the local clipboard change is a self-echo and must be dropped.
func (s *SyncState) IsLastReceived(hash string) bool {
	if hash == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReceivedHash == hash
}

// SetLastSent records the SHA-256 hash of an item dispatched outbound.
func (s *SyncState) SetLastSent(hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSentHash = hash
	s.currentLocalHash = hash
}

// IsLastSent returns true if hash matches the item most recently dispatched outbound.
// If true, the user simply copied the same item again, so it can be safely deduplicated.
func (s *SyncState) IsLastSent(hash string) bool {
	if hash == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSentHash == hash
}

// SetCurrentLocal records the SHA-256 hash of the currently active local clipboard content.
func (s *SyncState) SetCurrentLocal(hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentLocalHash = hash
}

// CurrentLocalHash returns the SHA-256 hash of the currently active local clipboard content.
func (s *SyncState) CurrentLocalHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentLocalHash
}
