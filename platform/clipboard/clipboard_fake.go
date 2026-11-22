package clipboard

import (
	"context"
	"sync"
)

// FakeClipboard is an in-memory implementation of the Clipboard interface
// designed for deterministic, zero-dependency unit tests.
type FakeClipboard struct {
	mu          sync.RWMutex
	current     *Item
	subscribers []chan struct{}
}

// NewFake creates an empty FakeClipboard.
func NewFake() *FakeClipboard {
	return &FakeClipboard{}
}

// Read returns a copy of the current clipboard item, or ErrEmpty if empty.
func (f *FakeClipboard) Read() (*Item, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.current == nil || len(f.current.Data) == 0 {
		return nil, ErrEmpty
	}

	// Return a copy so external callers cannot mutate internal state
	dataCopy := make([]byte, len(f.current.Data))
	copy(dataCopy, f.current.Data)

	return &Item{
		Kind: f.current.Kind,
		Data: dataCopy,
		Mime: f.current.Mime,
	}, nil
}

// Write updates the clipboard with a copy of the given item and
// non-blockingly notifies all active watchers.
func (f *FakeClipboard) Write(item *Item) error {
	f.mu.Lock()

	if item == nil {
		f.current = nil
	} else {
		dataCopy := make([]byte, len(item.Data))
		copy(dataCopy, item.Data)
		f.current = &Item{
			Kind: item.Kind,
			Data: dataCopy,
			Mime: item.Mime,
		}
	}

	// Capture subscribers slice while holding lock
	subs := make([]chan struct{}, len(f.subscribers))
	copy(subs, f.subscribers)
	f.mu.Unlock()

	// Notify subscribers without blocking
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}

	return nil
}

// Watch returns a channel that emits whenever Write or TriggerChange is called.
// The channel is closed and removed when ctx is cancelled.
func (f *FakeClipboard) Watch(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)

	f.mu.Lock()
	f.subscribers = append(f.subscribers, ch)
	f.mu.Unlock()

	go func() {
		<-ctx.Done()

		f.mu.Lock()
		defer f.mu.Unlock()

		// Remove channel from subscribers list
		for i, sub := range f.subscribers {
			if sub == ch {
				f.subscribers = append(f.subscribers[:i], f.subscribers[i+1:]...)
				break
			}
		}
		close(ch)
	}()

	return ch
}

// TriggerChange manually emits an event to all watchers without changing
// the stored item. Useful for simulating external OS clipboard updates.
func (f *FakeClipboard) TriggerChange() {
	f.mu.RLock()
	subs := make([]chan struct{}, len(f.subscribers))
	copy(subs, f.subscribers)
	f.mu.RUnlock()

	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
