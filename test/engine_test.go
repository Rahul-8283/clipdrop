package test

import (
	"context"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
)

func newTestEngine(t *testing.T, modifyCfg ...func(*config.Config)) (*engine.Engine, *clipboard.FakeClipboard) {
	t.Helper()
	cfg := config.Defaults()
	for _, fn := range modifyCfg {
		fn(&cfg)
	}
	fake := clipboard.NewFake()
	eng := engine.New(&cfg, fake)
	return eng, fake
}

func TestEngine_OutboundDetection(t *testing.T) {
	eng, fake := newTestEngine(t)

	item := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte("hello clipdrop"),
		Mime: "text/plain; charset=utf-8",
	}
	if err := fake.Write(item); err != nil {
		t.Fatalf("failed to write to fake: %v", err)
	}

	eng.ProcessLocalChange()

	select {
	case evt := <-eng.Outbound():
		if string(evt.Item.Data) != "hello clipdrop" {
			t.Fatalf("unexpected data: %s", string(evt.Item.Data))
		}
		expectedHash := engine.ComputeHash([]byte("hello clipdrop"))
		if evt.Hash != expectedHash {
			t.Fatalf("unexpected hash: %s, want %s", evt.Hash, expectedHash)
		}
	default:
		t.Fatal("expected outbound event, but channel was empty")
	}
}

func TestEngine_Deduplication(t *testing.T) {
	eng, fake := newTestEngine(t)

	item := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte("duplicate me"),
		Mime: "text/plain; charset=utf-8",
	}
	_ = fake.Write(item)

	// First copy: should emit
	eng.ProcessLocalChange()
	select {
	case <-eng.Outbound():
		// Success
	default:
		t.Fatal("expected first copy to emit event")
	}

	// Second copy of the exact same content: should be dropped as duplicate
	eng.ProcessLocalChange()
	select {
	case evt := <-eng.Outbound():
		t.Fatalf("unexpected event for duplicate copy: %+v", evt)
	default:
		// Success: deduplicated!
	}
}

func TestEngine_EchoSuppression(t *testing.T) {
	eng, _ := newTestEngine(t)

	remoteItem := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte("message from peer laptop"),
		Mime: "text/plain; charset=utf-8",
	}
	remoteHash := engine.ComputeHash(remoteItem.Data)

	// Inbound application simulates receiving content from a remote peer
	if err := eng.ApplyInbound(remoteItem, remoteHash); err != nil {
		t.Fatalf("ApplyInbound failed: %v", err)
	}

	// The local clipboard watcher would now fire in response to that write:
	eng.ProcessLocalChange()

	// Assert that NO outbound event was emitted (echo loop suppressed)
	select {
	case evt := <-eng.Outbound():
		t.Fatalf("FATAL: echo loop occurred! Event was re-emitted: %+v", evt)
	default:
		// Success: echo suppressed!
	}
}

func TestEngine_PolicyImagesOnly(t *testing.T) {
	eng, fake := newTestEngine(t, func(c *config.Config) {
		c.ImagesOnly = true
	})

	// Text item should be dropped under ImagesOnly
	textItem := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte("text should be ignored"),
		Mime: "text/plain; charset=utf-8",
	}
	_ = fake.Write(textItem)
	eng.ProcessLocalChange()

	select {
	case evt := <-eng.Outbound():
		t.Fatalf("text should have been dropped under ImagesOnly, got: %+v", evt)
	default:
		// Success
	}

	// PNG image item should pass through
	pngData := makeMockPNG(800, 600)
	imgItem := &clipboard.Item{
		Kind: clipboard.KindImage,
		Data: pngData,
		Mime: "image/png",
	}
	_ = fake.Write(imgItem)
	eng.ProcessLocalChange()

	select {
	case evt := <-eng.Outbound():
		if evt.Item.Kind != clipboard.KindImage {
			t.Fatalf("expected image event, got %s", evt.Item.Kind)
		}
	default:
		t.Fatal("expected PNG image to emit event under ImagesOnly")
	}
}

func TestEngine_InvalidImageDropped(t *testing.T) {
	eng, fake := newTestEngine(t)

	// Fake image with invalid JPEG header
	imgItem := &clipboard.Item{
		Kind: clipboard.KindImage,
		Data: []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10},
		Mime: "image/png",
	}
	_ = fake.Write(imgItem)
	eng.ProcessLocalChange()

	select {
	case evt := <-eng.Outbound():
		t.Fatalf("invalid image should have been dropped, got: %+v", evt)
	default:
		// Success
	}
}

func TestEngine_RunLifecycle(t *testing.T) {
	eng, fake := newTestEngine(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- eng.Run(ctx)
	}()

	// Allow goroutine to start and register its watch channel
	time.Sleep(50 * time.Millisecond)

	// Write an item through the fake watcher
	item := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte("lifecycle test"),
		Mime: "text/plain; charset=utf-8",
	}
	_ = fake.Write(item)

	select {
	case evt := <-eng.Outbound():
		if string(evt.Item.Data) != "lifecycle test" {
			t.Fatalf("unexpected data: %s", string(evt.Item.Data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound event in Run loop")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit promptly after context cancel")
	}
}
