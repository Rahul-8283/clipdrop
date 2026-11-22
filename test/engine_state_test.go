package test

import (
	"sync"
	"testing"

	"github.com/Rahul-8283/clipdrop/engine"
)

func TestComputeHash(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "empty byte slice",
			in:   []byte{},
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "hello text",
			in:   []byte("hello"),
			want: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.ComputeHash(tc.in)
			if got != tc.want {
				t.Fatalf("ComputeHash(%q) = %s, want %s", string(tc.in), got, tc.want)
			}
		})
	}
}

func TestSyncState_EchoDetection(t *testing.T) {
	s := engine.NewSyncState()
	testHash := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	if s.IsLastReceived(testHash) {
		t.Fatal("expected IsLastReceived to be false initially")
	}

	s.SetLastReceived(testHash)

	if !s.IsLastReceived(testHash) {
		t.Fatal("expected IsLastReceived to be true after SetLastReceived")
	}

	if s.IsLastReceived("different-hash") {
		t.Fatal("expected IsLastReceived to be false for a different hash")
	}

	if s.IsLastReceived("") {
		t.Fatal("expected empty hash check to return false")
	}
}

func TestSyncState_Deduplication(t *testing.T) {
	s := engine.NewSyncState()
	testHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if s.IsLastSent(testHash) {
		t.Fatal("expected IsLastSent to be false initially")
	}

	s.SetLastSent(testHash)

	if !s.IsLastSent(testHash) {
		t.Fatal("expected IsLastSent to be true after SetLastSent")
	}

	if s.IsLastSent("different-hash") {
		t.Fatal("expected IsLastSent to be false for a different hash")
	}

	if s.IsLastSent("") {
		t.Fatal("expected empty hash check to return false")
	}
}

func TestSyncState_Concurrency(t *testing.T) {
	s := engine.NewSyncState()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(val string) {
			defer wg.Done()
			s.SetLastReceived(val)
			_ = s.IsLastReceived(val)
		}("hash-recv")

		go func(val string) {
			defer wg.Done()
			s.SetLastSent(val)
			_ = s.IsLastSent(val)
		}("hash-sent")
	}

	wg.Wait()
}
