package test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/platform/clipboard"
)

func TestFakeClipboard_ReadEmpty(t *testing.T) {
	fc := clipboard.NewFake()

	item, err := fc.Read()
	if !errors.Is(err, clipboard.ErrEmpty) {
		t.Fatalf("expected ErrEmpty, got %v (item: %v)", err, item)
	}
}

func TestFakeClipboard_WriteAndRead(t *testing.T) {
	fc := clipboard.NewFake()

	orig := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte("hello clipdrop"),
		Mime: "text/plain; charset=utf-8",
	}

	if err := fc.Write(orig); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	read, err := fc.Read()
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if read.Kind != orig.Kind || string(read.Data) != string(orig.Data) || read.Mime != orig.Mime {
		t.Fatalf("read item mismatch: got %+v, want %+v", read, orig)
	}

	// Verify deep copy: mutating orig Data shouldn't affect read Data
	orig.Data[0] = 'X'
	read2, _ := fc.Read()
	if string(read2.Data) != "hello clipdrop" {
		t.Fatalf("FakeClipboard did not make defensive copy, got %s", string(read2.Data))
	}
}

func TestFakeClipboard_Watch(t *testing.T) {
	fc := clipboard.NewFake()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watchCh := fc.Watch(ctx)

	// Writing should trigger watch channel
	item := &clipboard.Item{
		Kind: clipboard.KindText,
		Data: []byte("test event"),
		Mime: "text/plain; charset=utf-8",
	}
	if err := fc.Write(item); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	select {
	case <-watchCh:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for watch event on Write")
	}

	// TriggerChange should also emit
	fc.TriggerChange()
	select {
	case <-watchCh:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for watch event on TriggerChange")
	}

	// Cancelling context should close channel
	cancel()
	select {
	case _, ok := <-watchCh:
		if ok {
			// might drain previous event if any, wait for close
			for range watchCh {
			}
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for watchCh to close on cancel")
	}
}
