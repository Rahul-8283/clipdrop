package app

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/netx/discovery"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/store"
)

const (
	// DefaultHeartbeatInterval defines the 5-second presence heartbeat period.
	DefaultHeartbeatInterval = 5 * time.Second

	// DefaultPingTimeout is the execution budget for individual ping probes.
	DefaultPingTimeout = 3 * time.Second
)

// Pinger defines the network ping capability of transport.Client.
type Pinger interface {
	Ping(ctx context.Context, addr string) (*transport.PingResponse, error)
}

// PresenceMonitor executes background heartbeat checks on trusted peers,
// tracks online state, updates store timestamps, and emits edge-triggered logs.
type PresenceMonitor struct {
	cfg      *config.Config
	store    *store.Store
	client   Pinger
	resolver *discovery.Resolver
	interval time.Duration
	timeout  time.Duration
	online   map[string]bool
	mu       sync.RWMutex
}

// NewPresenceMonitor constructs a PresenceMonitor backed by core dependencies.
func NewPresenceMonitor(cfg *config.Config, st *store.Store, client *transport.Client, resolver *discovery.Resolver) *PresenceMonitor {
	return NewPresenceMonitorWithPinger(cfg, st, client, resolver)
}

// NewPresenceMonitorWithPinger allows injecting a custom Pinger (used in tests).
func NewPresenceMonitorWithPinger(cfg *config.Config, st *store.Store, pinger Pinger, resolver *discovery.Resolver) *PresenceMonitor {
	return &PresenceMonitor{
		cfg:      cfg,
		store:    st,
		client:   pinger,
		resolver: resolver,
		interval: DefaultHeartbeatInterval,
		timeout:  DefaultPingTimeout,
		online:   make(map[string]bool),
	}
}

// SetInterval overrides the default heartbeat interval.
func (pm *PresenceMonitor) SetInterval(d time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.interval = d
}

// SetTimeout overrides the per-ping probe timeout.
func (pm *PresenceMonitor) SetTimeout(d time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.timeout = d
}

// IsOnline reports whether the specified device is currently reachable.
func (pm *PresenceMonitor) IsOnline(deviceID string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.online[deviceID]
}

// Start begins the 5-second heartbeat loop and runs until ctx is cancelled.
func (pm *PresenceMonitor) Start(ctx context.Context) error {
	pm.mu.RLock()
	interval := pm.interval
	pm.mu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Execute initial check immediately
	pm.ProbeAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			pm.ProbeAll(ctx)
		}
	}
}

// ProbeAll executes a single presence probe across all trusted devices.
func (pm *PresenceMonitor) ProbeAll(ctx context.Context) {
	if pm.store == nil || pm.client == nil {
		return
	}

	devices := pm.store.List()
	for _, dev := range devices {
		if ctx.Err() != nil {
			return
		}
		pm.probeDevice(ctx, dev)
	}
}

func (pm *PresenceMonitor) probeDevice(ctx context.Context, dev *store.Device) {
	addr, err := pm.resolveAddress(dev.ID)
	if err != nil {
		pm.markOffline(dev)
		return
	}

	pm.mu.RLock()
	timeout := pm.timeout
	pm.mu.RUnlock()

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_, err = pm.client.Ping(pingCtx, addr)
	if err != nil {
		pm.markOffline(dev)
		return
	}

	pm.markOnline(dev, addr)
}

func (pm *PresenceMonitor) resolveAddress(deviceID string) (string, error) {
	if pm.resolver == nil {
		return "", discovery.ErrPeerOffline
	}
	return pm.resolver.Resolve(deviceID)
}

func (pm *PresenceMonitor) markOnline(dev *store.Device, addr string) {
	pm.mu.Lock()
	wasOnline := pm.online[dev.ID]
	pm.online[dev.ID] = true
	pm.mu.Unlock()

	if !wasOnline {
		slog.Info("peer is online", "name", dev.Name, "addr", addr)
	}

	_ = pm.store.UpdateLastSeen(dev.ID, addr)
}

func (pm *PresenceMonitor) markOffline(dev *store.Device) {
	pm.mu.Lock()
	wasOnline := pm.online[dev.ID]
	pm.online[dev.ID] = false
	pm.mu.Unlock()

	if wasOnline {
		slog.Info("peer went offline", "name", dev.Name)
	}
}
