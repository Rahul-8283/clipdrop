package clipboard

import (
	"context"
	"errors"
	"fmt"
	"time"

	xclipboard "golang.design/x/clipboard"
)

// RealClipboard wraps golang.design/x/clipboard to interact with the
// underlying host operating system pasteboard.
type RealClipboard struct{}

// NewReal initializes the native clipboard subsystem via clipboard.Init()
// and returns a RealClipboard instance ready for use.
// It returns ErrUnavailable if the host clipboard subsystem is inaccessible.
func NewReal() (*RealClipboard, error) {
	if err := xclipboard.Init(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return &RealClipboard{}, nil
}

// Read fetches the current content from the host clipboard.
// It prioritizes screenshots/images (PNG) first; if no image is present,
// it falls back to text. Retries up to 3 times to handle temporary OS lock contention.
func (r *RealClipboard) Read() (*Item, error) {
	// First check for image content (e.g. screenshot)
	imgData, err := readWithRetry(xclipboard.FmtImage)
	if err == nil && len(imgData) > 0 {
		return &Item{
			Kind: KindImage,
			Data: imgData,
			Mime: "image/png",
		}, nil
	}

	// Then check for plain text content
	txtData, err := readWithRetry(xclipboard.FmtText)
	if err == nil && len(txtData) > 0 {
		return &Item{
			Kind: KindText,
			Data: txtData,
			Mime: "text/plain; charset=utf-8",
		}, nil
	}

	if errors.Is(err, xclipboard.ErrUnavailable) {
		return nil, ErrUnavailable
	}
	return nil, ErrEmpty
}

// Write replaces the host clipboard content with the given item.
func (r *RealClipboard) Write(item *Item) error {
	if item == nil || len(item.Data) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var format xclipboard.Format
	switch item.Kind {
	case KindImage:
		format = xclipboard.FmtImage
	case KindText:
		format = xclipboard.FmtText
	default:
		return ErrUnsupportedFormat
	}

	_, err := xclipboard.Write(ctx, format, item.Data)
	if err != nil {
		if errors.Is(err, xclipboard.ErrUnavailable) {
			return ErrUnavailable
		}
		return err
	}
	return nil
}

// Watch listens for OS clipboard changes across both image and text formats,
// multiplexing them into a single non-blocking signal channel.
func (r *RealClipboard) Watch(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	nativeCh := xclipboard.Watch(ctx, xclipboard.FmtImage, xclipboard.FmtText)

	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-nativeCh:
				if !ok {
					return
				}
				select {
				case ch <- struct{}{}:
				default:
					// Signal already pending in buffer; avoid blocking
				}
			}
		}
	}()

	return ch
}

// readWithRetry performs reads with short backoffs to mitigate OS clipboard
// lock contention (particularly on Windows where other apps briefly hold locks).
func readWithRetry(format xclipboard.Format) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(20 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		data, err := xclipboard.Read(ctx, format)
		cancel()

		if err == nil {
			return data, nil
		}
		lastErr = err

		// If the clipboard simply contains no data for this format, do not retry
		if errors.Is(err, xclipboard.ErrNoData) {
			return nil, err
		}
	}
	return nil, lastErr
}
