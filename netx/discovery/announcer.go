package discovery

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/grandcat/zeroconf"
)

// Announcer manages the zeroconf mDNS service publication for Clipdrop.
type Announcer struct {
	mu     sync.Mutex
	server *zeroconf.Server
	ident  *identity.Identity
	port   int
	status string
}

// Announce registers a new _clipdrop._tcp mDNS service instance and begins broadcasting.
func Announce(ctx context.Context, ident *identity.Identity, port int, status string) (*Announcer, error) {
	if ident == nil {
		return nil, errors.New("discovery: identity is required")
	}
	if port <= 0 {
		return nil, errors.New("discovery: valid port is required")
	}
	if status == "" {
		status = StatusReady
	}

	hostName := ident.Certificate.Subject.CommonName
	if hostName == "" {
		hostName = "clipdrop-node"
	}

	instance := BuildInstanceName(ident.DeviceID, hostName)
	txt := BuildTXT(Record{
		ID:     ident.DeviceID,
		Name:   hostName,
		OS:     runtime.GOOS,
		Proto:  "1",
		Status: status,
	})

	srv, err := zeroconf.Register(instance, ServiceType, Domain, port, txt, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: failed to register mDNS service: %w", err)
	}

	a := &Announcer{
		server: srv,
		ident:  ident,
		port:   port,
		status: status,
	}

	// Unregister automatically if context is cancelled
	go func() {
		<-ctx.Done()
		a.Shutdown()
	}()

	return a, nil
}

// SetStatus dynamically updates the TXT record status attribute between "ready" and "pairing".
func (a *Announcer) SetStatus(status string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if status == "" {
		status = StatusReady
	}
	if a.status == status && a.server != nil {
		return nil
	}
	a.status = status

	if a.server != nil {
		a.server.Shutdown()
		a.server = nil
	}

	hostName := a.ident.Certificate.Subject.CommonName
	if hostName == "" {
		hostName = "clipdrop-node"
	}

	instance := BuildInstanceName(a.ident.DeviceID, hostName)
	txt := BuildTXT(Record{
		ID:     a.ident.DeviceID,
		Name:   hostName,
		OS:     runtime.GOOS,
		Proto:  "1",
		Status: status,
	})

	srv, err := zeroconf.Register(instance, ServiceType, Domain, a.port, txt, nil)
	if err != nil {
		return fmt.Errorf("discovery: failed to re-register mDNS service: %w", err)
	}
	a.server = srv
	return nil
}

// Status returns the current advertised status of the announcer.
func (a *Announcer) Status() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

// Shutdown unregisters the mDNS service cleanly from the network.
func (a *Announcer) Shutdown() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.server != nil {
		a.server.Shutdown()
		a.server = nil
	}
}
