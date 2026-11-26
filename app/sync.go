package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/identity"
	"github.com/Rahul-8283/clipdrop/netx/discovery"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/platform/screenshots"
	"github.com/Rahul-8283/clipdrop/store"
)

// SyncPipeline coordinates all local and network subsystems into a unified,
// bidirectional clipboard synchronization service.
type SyncPipeline struct {
	cfg       *config.Config
	ident     *identity.Identity
	store     *store.Store
	clip      clipboard.Clipboard
	engine    *engine.Engine
	server    *transport.Server
	client    *transport.Client
	announcer *discovery.Announcer
	browser   *discovery.Browser
	resolver  *discovery.Resolver
	presence  *PresenceMonitor
	listener  net.Listener
	mu        sync.Mutex
}

// NewSyncPipeline initializes all core subsystems for normal operation.
func NewSyncPipeline(cfg *config.Config, clip clipboard.Clipboard) (*SyncPipeline, error) {
	return NewSyncPipelineWithComponents(cfg, nil, nil, clip, nil)
}

// NewSyncPipelineWithListener initializes subsystems with an optional custom net.Listener.
func NewSyncPipelineWithListener(cfg *config.Config, clip clipboard.Clipboard, listener net.Listener) (*SyncPipeline, error) {
	return NewSyncPipelineWithComponents(cfg, nil, nil, clip, listener)
}

// NewSyncPipelineWithComponents initializes subsystems allowing custom identity, store, clipboard, and listener.
func NewSyncPipelineWithComponents(cfg *config.Config, ident *identity.Identity, st *store.Store, clip clipboard.Clipboard, listener net.Listener) (*SyncPipeline, error) {
	if cfg == nil {
		return nil, errors.New("sync: config is required")
	}

	configDir := cfg.ConfigDir
	if configDir == "" {
		var err error
		configDir, err = config.Dir()
		if err != nil {
			return nil, fmt.Errorf("sync: resolving config directory: %w", err)
		}
	}

	var err error
	if ident == nil {
		ident, err = identity.LoadOrGenerate(configDir, cfg.DeviceName)
		if err != nil {
			return nil, fmt.Errorf("sync: loading identity: %w", err)
		}
	}

	if st == nil {
		st, err = store.New(filepath.Join(configDir, "trusted_devices.json"))
		if err != nil {
			return nil, fmt.Errorf("sync: loading trusted devices store: %w", err)
		}
	}

	if clip == nil {
		clip, err = clipboard.NewReal()
		if err != nil {
			return nil, fmt.Errorf("sync: initializing clipboard: %w", err)
		}
	}

	eng := engine.New(cfg, clip)
	resolver := discovery.NewResolver(cfg, st)
	client := transport.NewClient(ident, st)

	var srv *transport.Server
	if listener != nil {
		srv, err = transport.NewServerWithListener(cfg, ident, st, eng, listener)
	} else {
		srv, err = transport.NewServer(cfg, ident, st, eng)
	}
	if err != nil {
		return nil, fmt.Errorf("sync: creating transport server: %w", err)
	}

	browser := discovery.NewBrowser(resolver)
	presence := NewPresenceMonitor(cfg, st, client, resolver)

	return &SyncPipeline{
		cfg:      cfg,
		ident:    ident,
		store:    st,
		clip:     clip,
		engine:   eng,
		server:   srv,
		client:   client,
		browser:  browser,
		resolver: resolver,
		presence: presence,
		listener: listener,
	}, nil
}

// Engine returns the underlying clipboard engine.
func (p *SyncPipeline) Engine() *engine.Engine {
	return p.engine
}

// Store returns the trusted devices store.
func (p *SyncPipeline) Store() *store.Store {
	return p.store
}

// Resolver returns the mDNS address resolver.
func (p *SyncPipeline) Resolver() *discovery.Resolver {
	return p.resolver
}

// SetClient overrides the transport client (used in loopback/in-memory tests).
func (p *SyncPipeline) SetClient(c *transport.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.client = c
}

// Run starts all core subsystems under root context and blocks until cancelled.
func (p *SyncPipeline) Run(ctx context.Context) error {
	slog.Info("sync: watching clipboard in foreground",
		"images_only", p.cfg.ImagesOnly,
		"device", p.cfg.DeviceName,
	)

	// 1. Announce mDNS service with status=ready
	announcer, annErr := discovery.Announce(ctx, p.ident, p.cfg.Port, discovery.StatusReady)
	if announcer != nil {
		p.announcer = announcer
		defer announcer.Shutdown()
	}
	if annErr != nil {
		slog.Debug("mdns announcer unavailable", "err", annErr)
	}

	// 2. Start mTLS sync server
	serverErrCh := make(chan error, 1)
	go func() {
		if err := p.server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	// 3. Start mDNS browser
	go func() {
		if err := p.browser.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Debug("discovery browser stopped", "err", err)
		}
	}()

	// 4. Start presence heartbeat monitor
	go func() {
		if err := p.presence.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Debug("presence monitor stopped", "err", err)
		}
	}()

	// 5. Start outbound dispatch worker
	go p.dispatchLoop(ctx)

	// 6. Optional screenshot directory watcher
	if p.cfg.WatchScreenshots {
		go func() {
			watcher := screenshots.NewWatcher("", p.engine)
			if err := watcher.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Debug("screenshot watcher stopped", "err", err)
			}
		}()
	}

	// 7. Run clipboard engine loop (blocks until ctx is cancelled)
	engineErrCh := make(chan error, 1)
	go func() {
		engineErrCh <- p.engine.Run(ctx)
	}()

	// Wait for context cancellation or fatal subsystem error
	var runErr error
	select {
	case <-ctx.Done():
		runErr = ctx.Err()
	case err := <-engineErrCh:
		runErr = err
	case err := <-serverErrCh:
		runErr = err
	}

	// Graceful teardown within 3-second budget
	p.teardown()

	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}

func (p *SyncPipeline) teardown() {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.browser.Stop()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		defer cancel()
		if err := p.server.Stop(shutdownCtx); err != nil {
			_ = p.server.Close()
		}
	}()

	if p.announcer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.announcer.Shutdown()
		}()
	}

	wg.Wait()
}

// dispatchLoop continuously consumes clipboard events from the engine and dispatches to peers.
func (p *SyncPipeline) dispatchLoop(ctx context.Context) {
	outbound := p.engine.Outbound()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-outbound:
			if !ok {
				return
			}
			p.dispatchItem(ctx, evt)
		}
	}
}

// dispatchItem transmits a clipboard event to all currently reachable trusted peers.
func (p *SyncPipeline) dispatchItem(ctx context.Context, evt engine.OutboundEvent) {
	if evt.Item == nil {
		return
	}

	trustedPeers := p.store.List()
	if len(trustedPeers) == 0 {
		slog.Debug("peer offline, item dropped")
		return
	}

	type target struct {
		peer *store.Device
		addr string
	}
	var targets []target

	for _, peer := range trustedPeers {
		addr, err := p.resolver.Resolve(peer.ID)
		if err == nil && addr != "" {
			targets = append(targets, target{peer: peer, addr: addr})
		}
	}

	if len(targets) == 0 {
		slog.Debug("peer offline, item dropped")
		return
	}

	req := &transport.OfferRequest{
		ID:     fmt.Sprintf("%d", time.Now().UnixNano()),
		Kind:   string(evt.Item.Kind),
		Size:   int64(len(evt.Item.Data)),
		Mime:   evt.Item.Mime,
		Sha256: evt.Hash,
	}

	p.mu.Lock()
	client := p.client
	p.mu.Unlock()

	var wg sync.WaitGroup
	for _, tgt := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			p.sendToPeer(ctx, client, t.peer, t.addr, req, evt.Item)
		}(tgt)
	}
	wg.Wait()
}

func (p *SyncPipeline) sendToPeer(ctx context.Context, client *transport.Client, peer *store.Device, addr string, req *transport.OfferRequest, item *clipboard.Item) {
	if client == nil {
		return
	}

	offerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resp, err := client.Offer(offerCtx, addr, req)
	if err != nil {
		slog.Debug("offer failed", "peer", peer.Name, "err", err)
		return
	}

	if resp.Action == transport.ActionSkip {
		slog.Debug("peer skipped item", "peer", peer.Name, "reason", resp.Reason)
		return
	}

	if resp.Action == transport.ActionSend {
		uploadCtx, cancelUpload := context.WithTimeout(ctx, 10*time.Second)
		defer cancelUpload()

		err := client.Upload(
			uploadCtx,
			addr,
			req.ID,
			item.Data,
			item.Kind,
			item.Mime,
			req.Sha256,
		)
		if err != nil {
			slog.Debug("upload failed", "peer", peer.Name, "err", err)
			return
		}

		slog.Info("sent clipboard item",
			"kind", item.Kind,
			"size", len(item.Data),
			"peer", peer.Name,
		)
	}
}
