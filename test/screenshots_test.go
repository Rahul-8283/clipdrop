package test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/engine"
	"github.com/Rahul-8283/clipdrop/platform/clipboard"
	"github.com/Rahul-8283/clipdrop/platform/screenshots"
)

func TestScreenshots_ResolveDir(t *testing.T) {
	dir, err := screenshots.ResolveScreencaptureDir()
	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Fatalf("unexpected error on darwin: %v", err)
		}
		if dir == "" {
			t.Fatal("expected non-empty screencapture directory on darwin")
		}
	} else {
		if err == nil {
			t.Fatal("expected error on non-darwin platform")
		}
	}
}

func TestScreenshots_Watcher_Debounce_And_Ingestion(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("skipping macOS-specific screenshot watcher test on non-darwin")
	}

	watchDir := t.TempDir()
	cfg := config.Defaults()
	fakeClip := clipboard.NewFake()
	eng := engine.New(&cfg, fakeClip)

	watcher := screenshots.NewWatcher(watchDir, eng).WithPollInterval(30 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = watcher.Start(ctx)
	}()

	samplePNG := makeMockPNG(8, 8)
	targetFile := filepath.Join(watchDir, "Screen Shot 2026-11-24.png")

	// 1. Partial write (file size still growing / unstable)
	halfLen := len(samplePNG) / 2
	if err := os.WriteFile(targetFile, samplePNG[:halfLen], 0644); err != nil {
		t.Fatalf("failed to write partial png: %v", err)
	}

	// Wait 40ms: watcher should observe halfLen, but count is only 1
	time.Sleep(40 * time.Millisecond)

	// Append remainder of file: size changes
	f, err := os.OpenFile(targetFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open file for append: %v", err)
	}
	if _, err := f.Write(samplePNG[halfLen:]); err != nil {
		_ = f.Close()
		t.Fatalf("failed to append bytes: %v", err)
	}
	_ = f.Close()

	// 2. Poll until engine emits outbound event
	outCh := eng.Outbound()
	var receivedEvent engine.OutboundEvent
	select {
	case evt := <-outCh:
		receivedEvent = evt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for debounced screenshot ingestion")
	}

	if receivedEvent.Item == nil {
		t.Fatal("expected non-nil item in outbound event")
	}
	if receivedEvent.Item.Kind != clipboard.KindImage {
		t.Fatalf("expected kind image, got %s", receivedEvent.Item.Kind)
	}
	if !bytes.Equal(receivedEvent.Item.Data, samplePNG) {
		t.Fatal("ingested image data does not match written PNG bytes")
	}

	// 3. Verify deduplication: watcher must not re-emit already processed file
	select {
	case evt := <-outCh:
		t.Fatalf("unexpected duplicate event received: %+v", evt)
	case <-time.After(150 * time.Millisecond):
		// Expected: no duplicate event
	}
}

func TestScreenshots_Watcher_InvalidPNG_Ignored(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("skipping macOS-specific screenshot watcher test on non-darwin")
	}

	watchDir := t.TempDir()
	cfg := config.Defaults()
	fakeClip := clipboard.NewFake()
	eng := engine.New(&cfg, fakeClip)

	watcher := screenshots.NewWatcher(watchDir, eng).WithPollInterval(25 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = watcher.Start(ctx)
	}()

	// 1. Corrupt PNG
	corruptFile := filepath.Join(watchDir, "Corrupt Screenshot.png")
	_ = os.WriteFile(corruptFile, []byte("this is not a valid png file header"), 0644)

	// 2. Non-PNG file
	textFile := filepath.Join(watchDir, "Notes.txt")
	_ = os.WriteFile(textFile, []byte("plain text document"), 0644)

	// Wait across multiple polling cycles and assert nothing is ingested
	select {
	case evt := <-eng.Outbound():
		t.Fatalf("unexpected event for invalid or non-PNG file: %+v", evt)
	case <-time.After(200 * time.Millisecond):
		// Success: invalid files ignored
	}
}
