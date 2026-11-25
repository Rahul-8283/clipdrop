package engine

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"unicode/utf8"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/imaging"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
)

// OutboundEvent represents a validated, non-echo, non-duplicate clipboard item
// ready for dispatch to remote peers.
type OutboundEvent struct {
	Item *clipboard.Item
	Hash string
}

// Engine coordinates clipboard change detection, policy filtering,
// echo loop suppression, and inbound clipboard application.
type Engine struct {
	cfg   *config.Config
	clip  clipboard.Clipboard
	state *SyncState
	outCh chan OutboundEvent
}

// New constructs an Engine with the provided configuration and clipboard interface.
func New(cfg *config.Config, clip clipboard.Clipboard) *Engine {
	return &Engine{
		cfg:   cfg,
		clip:  clip,
		state: NewSyncState(),
		outCh: make(chan OutboundEvent, 16),
	}
}

// Outbound returns the channel emitting validated clipboard events.
func (e *Engine) Outbound() <-chan OutboundEvent {
	return e.outCh
}

// State returns the underlying SyncState instance.
func (e *Engine) State() *SyncState {
	return e.state
}

// Run executes the engine's main event loop, listening for clipboard change
// notifications until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	watchCh := e.clip.Watch(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-watchCh:
			if !ok {
				return nil
			}
			e.ProcessLocalChange()
		}
	}
}

// ProcessLocalChange executes the outbound evaluation pipeline for a local
// clipboard modification.
func (e *Engine) ProcessLocalChange() {
	item, err := e.clip.Read()
	if err != nil {
		if errors.Is(err, clipboard.ErrEmpty) {
			slog.Debug("engine: clipboard is empty")
			return
		}
		slog.Debug("engine: failed to read clipboard", "err", err)
		return
	}
	e.ProcessItem(item)
}

// ProcessItem evaluates and dispatches an outbound item (e.g. from local clipboard
// or the optional screenshot directory watcher).
func (e *Engine) ProcessItem(item *clipboard.Item) {
	if item == nil {
		return
	}

	// 1. Policy check: suppress text if images-only is active
	if item.Kind == clipboard.KindText && (e.cfg.ImagesOnly || e.cfg.NoText) {
		slog.Debug("engine: dropping text copy due to images-only policy")
		return
	}

	// 2. Payload validation
	switch item.Kind {
	case clipboard.KindImage:
		info, err := imaging.ValidatePNG(item.Data)
		if err != nil {
			slog.Warn("engine: invalid image", "err", err)
			return
		}
		slog.Debug("engine: validated PNG image", "width", info.Width, "height", info.Height, "size", info.Size)

	case clipboard.KindText:
		if int64(len(item.Data)) > e.cfg.MaxTextBytes {
			slog.Warn("engine: text exceeds size limit", "size", len(item.Data), "max", e.cfg.MaxTextBytes)
			return
		}
		if !utf8.Valid(item.Data) {
			slog.Warn("engine: text payload contains invalid UTF-8")
			return
		}
		if len(bytes.TrimSpace(item.Data)) == 0 {
			slog.Debug("engine: ignoring empty or whitespace-only text")
			return
		}

	default:
		slog.Debug("engine: unsupported item kind", "kind", item.Kind)
		return
	}

	// 3. Compute SHA-256 digest
	hash := ComputeHash(item.Data)

	// 4. Echo loop check: did this item originate from a remote peer?
	if e.state.IsLastReceived(hash) {
		slog.Debug("engine: suppressing self-echo loop from peer", "hash", hash)
		return
	}

	// 5. Dedupe check: did the user copy the exact same item again?
	if e.state.IsLastSent(hash) {
		slog.Debug("engine: dropping duplicate local copy", "hash", hash)
		return
	}

	// 6. Update state and emit outbound event
	e.state.SetLastSent(hash)

	slog.Info("engine: detected clipboard change",
		"kind", item.Kind,
		"size", len(item.Data),
		"hash", hash,
	)

	select {
	case e.outCh <- OutboundEvent{Item: item, Hash: hash}:
	default:
		slog.Warn("engine: outbound event channel full, dropping event")
	}
}

// ApplyInbound applies an item received from a remote peer to the local OS clipboard.
// It records hash as LastReceived BEFORE invoking clipboard.Write, guaranteeing that
// when the local clipboard watcher fires in response to this write, it is recognized
// as a self-echo and suppressed.
func (e *Engine) ApplyInbound(item *clipboard.Item, hash string) error {
	e.state.SetLastReceived(hash)
	return e.clip.Write(item)
}
