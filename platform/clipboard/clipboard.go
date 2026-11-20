// Package clipboard defines the platform-agnostic clipboard abstraction,
// content types, and standard errors for Clipdrop.
package clipboard

import (
	"context"
	"errors"
)

// Standard clipboard errors.
var (
	// ErrEmpty is returned by Read when the clipboard contains no readable data.
	ErrEmpty = errors.New("clipboard is empty")

	// ErrUnsupportedFormat is returned when clipboard data cannot be parsed
	// as valid UTF-8 text or a supported image format.
	ErrUnsupportedFormat = errors.New("unsupported clipboard format")

	// ErrUnavailable is returned when the clipboard subsystem is locked,
	// uninitialized, or inaccessible by the operating system.
	ErrUnavailable = errors.New("clipboard unavailable")
)

// ItemKind indicates the classification of a clipboard payload.
type ItemKind string

const (
	// KindText denotes a plain-text payload encoded as UTF-8.
	KindText ItemKind = "text"

	// KindImage denotes a raster graphic payload encoded as PNG.
	KindImage ItemKind = "image"
)

// Item represents a normalized piece of clipboard content.
type Item struct {
	// Kind specifies whether the item is text or an image.
	Kind ItemKind

	// Data holds the raw byte content (UTF-8 text or raw PNG bytes).
	Data []byte

	// Mime indicates the MIME type ("text/plain; charset=utf-8" or "image/png").
	Mime string
}

// Clipboard defines the contract for reading, writing, and watching
// operating system or in-memory clipboards.
type Clipboard interface {
	// Read fetches the current content from the clipboard.
	// Returns ErrEmpty if there is no readable content.
	Read() (*Item, error)

	// Write replaces the current clipboard content with the provided Item.
	Write(item *Item) error

	// Watch returns a channel that emits a signal whenever the clipboard content changes.
	// The channel is closed when the provided context is cancelled.
	Watch(ctx context.Context) <-chan struct{}
}
