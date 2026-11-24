package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/grandcat/zeroconf"
)

// Browser listens for _clipdrop._tcp mDNS announcements and updates the Resolver.
type Browser struct {
	resolver *Resolver
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewBrowser creates a new Browser instance bound to a Resolver.
func NewBrowser(resolver *Resolver) *Browser {
	return &Browser{
		resolver: resolver,
		stopCh:   make(chan struct{}),
	}
}

// Start initiates browsing for _clipdrop._tcp announcements until ctx is cancelled or Stop is called.
func (b *Browser) Start(ctx context.Context) error {
	res, err := zeroconf.NewResolver(nil)
	if err != nil {
		return fmt.Errorf("discovery: failed to create zeroconf resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry, 32)
	browseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-b.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	go func() {
		for entry := range entries {
			b.HandleEntry(entry)
		}
	}()

	if err := res.Browse(browseCtx, ServiceType, Domain, entries); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("discovery: browse failed: %w", err)
	}

	return nil
}

// HandleEntry processes a single discovered ServiceEntry and registers it in the Resolver.
func (b *Browser) HandleEntry(entry *zeroconf.ServiceEntry) {
	if entry == nil || b.resolver == nil {
		return
	}

	rec := ParseTXT(entry.Text)
	if rec.ID == "" {
		return
	}

	// Prefer IPv4 address over IPv6
	var ip net.IP
	if len(entry.AddrIPv4) > 0 {
		ip = entry.AddrIPv4[0]
	} else if len(entry.AddrIPv6) > 0 {
		ip = entry.AddrIPv6[0]
	}

	if ip == nil {
		return
	}

	addr := fmt.Sprintf("%s:%d", ip.String(), entry.Port)
	b.resolver.UpdateFromMDNS(rec.ID, rec.Name, rec.Status, addr)
}

// Stop terminates the browser listener.
func (b *Browser) Stop() {
	b.stopOnce.Do(func() {
		close(b.stopCh)
	})
}
