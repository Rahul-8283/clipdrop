package discovery

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/store"
)

// ErrPeerOffline is returned when an address cannot be resolved across any tier.
var ErrPeerOffline = errors.New("discovery: peer offline, no reachable address")

// PeerAddress represents the active network location and state of a peer.
type PeerAddress struct {
	DeviceID string    `json:"device_id"`
	Name     string    `json:"name"`
	Address  string    `json:"address"` // "ip:port"
	Status   string    `json:"status"`  // "ready" or "pairing"
	LastSeen time.Time `json:"last_seen"`
}

// Resolver maintains an in-memory routing table mapping DeviceID -> PeerAddress
// and enforces the 3-tier address resolution hierarchy.
type Resolver struct {
	mu    sync.RWMutex
	peers map[string]*PeerAddress
	cfg   *config.Config
	store *store.Store
}

// NewResolver constructs a Resolver instance with configuration and trust store.
func NewResolver(cfg *config.Config, st *store.Store) *Resolver {
	return &Resolver{
		peers: make(map[string]*PeerAddress),
		cfg:   cfg,
		store: st,
	}
}

// UpdateFromMDNS records or updates an active mDNS service announcement.
func (r *Resolver) UpdateFromMDNS(deviceID, name, status, address string) {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if normID == "" || strings.TrimSpace(address) == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.peers[normID] = &PeerAddress{
		DeviceID: normID,
		Name:     name,
		Address:  address,
		Status:   status,
		LastSeen: time.Now(),
	}
}

// RemoveMDNS clears the active mDNS record for a peer.
func (r *Resolver) RemoveMDNS(deviceID string) {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if normID == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, normID)
}

// Get returns the active mDNS peer record if one currently exists.
func (r *Resolver) Get(deviceID string) (*PeerAddress, bool) {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if normID == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.peers[normID]
	if !ok || p == nil {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// Resolve returns the best network address (ip:port) for the target device following
// the strict 3-tier resolution hierarchy:
// Tier 1: Active mDNS discovered IP and port (freshest live network state).
// Tier 2: CLI --peer override from config (if configured).
// Tier 3: Stored LastAddress from trusted_devices.json.
func (r *Resolver) Resolve(deviceID string) (string, error) {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if normID == "" {
		return "", ErrPeerOffline
	}

	// Tier 1: Active mDNS discovery
	r.mu.RLock()
	mdnsPeer, hasMDNS := r.peers[normID]
	r.mu.RUnlock()

	if hasMDNS && mdnsPeer != nil && strings.TrimSpace(mdnsPeer.Address) != "" {
		return strings.TrimSpace(mdnsPeer.Address), nil
	}

	// Tier 2: CLI --peer override
	if r.cfg != nil && strings.TrimSpace(r.cfg.PeerAddr) != "" {
		return strings.TrimSpace(r.cfg.PeerAddr), nil
	}

	// Tier 3: Stored LastAddress from trust store
	if r.store != nil {
		dev, ok := r.store.Get(normID)
		if ok && dev != nil && strings.TrimSpace(dev.LastAddress) != "" {
			return strings.TrimSpace(dev.LastAddress), nil
		}
	}

	return "", ErrPeerOffline
}

// OnlinePeers returns a slice of all active peers currently discovered via mDNS.
func (r *Resolver) OnlinePeers() []*PeerAddress {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]*PeerAddress, 0, len(r.peers))
	for _, p := range r.peers {
		if p != nil {
			cp := *p
			list = append(list, &cp)
		}
	}
	return list
}
