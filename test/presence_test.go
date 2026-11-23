package test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rahul-8283/clipdrop/app"
	"github.com/Rahul-8283/clipdrop/config"
	"github.com/Rahul-8283/clipdrop/netx/discovery"
	"github.com/Rahul-8283/clipdrop/netx/transport"
	"github.com/Rahul-8283/clipdrop/store"
)

type mockPinger struct {
	mu        sync.Mutex
	pingErr   error
	pingCount int
	lastAddr  string
}

func (m *mockPinger) Ping(ctx context.Context, addr string) (*transport.PingResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pingCount++
	m.lastAddr = addr
	if m.pingErr != nil {
		return nil, m.pingErr
	}
	return &transport.PingResponse{
		DeviceName:      "remote-laptop",
		ProtocolVersion: 1,
		CurrentTime:     time.Now().Format(time.RFC3339),
	}, nil
}

func (m *mockPinger) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pingErr = err
}

func TestPresence_EdgeTriggeredLogging(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	dev := &store.Device{
		ID:          "peer-device-001",
		Name:        "remote-laptop",
		OS:          "windows",
		LastAddress: "192.168.1.100:47820",
	}
	if err := st.Add(dev); err != nil {
		t.Fatalf("failed to add device: %v", err)
	}

	cfg := config.Defaults()
	resolver := discovery.NewResolver(&cfg, st)
	pinger := &mockPinger{}

	pm := app.NewPresenceMonitorWithPinger(&cfg, st, pinger, resolver)

	// Capture slog messages to buffer
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	origLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(origLogger)

	ctx := context.Background()

	// Probe 1: Peer comes online -> Emits "peer is online" log
	pm.ProbeAll(ctx)
	if !pm.IsOnline(dev.ID) {
		t.Fatal("expected peer to be online after successful probe")
	}
	out1 := logBuf.String()
	if !strings.Contains(out1, "peer is online") || !strings.Contains(out1, "remote-laptop") {
		t.Fatalf("expected online log, got: %q", out1)
	}

	// Probe 2: Steady state (still online) -> Zero new logs
	logBuf.Reset()
	pm.ProbeAll(ctx)
	if logBuf.Len() != 0 {
		t.Fatalf("steady-state online probe emitted unexpected logs: %q", logBuf.String())
	}

	// Probe 3: Peer goes offline -> Emits "peer went offline" log
	pinger.setErr(errors.New("connection refused"))
	logBuf.Reset()
	pm.ProbeAll(ctx)
	if pm.IsOnline(dev.ID) {
		t.Fatal("expected peer to be offline after failed probe")
	}
	out3 := logBuf.String()
	if !strings.Contains(out3, "peer went offline") || !strings.Contains(out3, "remote-laptop") {
		t.Fatalf("expected offline log, got: %q", out3)
	}

	// Probe 4: Steady state (still offline) -> Zero new logs
	logBuf.Reset()
	pm.ProbeAll(ctx)
	if logBuf.Len() != 0 {
		t.Fatalf("steady-state offline probe emitted unexpected logs: %q", logBuf.String())
	}

	// Probe 5: Recovery -> Emits "peer is online" log
	pinger.setErr(nil)
	logBuf.Reset()
	pm.ProbeAll(ctx)
	if !pm.IsOnline(dev.ID) {
		t.Fatal("expected peer to be online after recovery probe")
	}
	out5 := logBuf.String()
	if !strings.Contains(out5, "peer is online") {
		t.Fatalf("expected recovery online log, got: %q", out5)
	}
}

func TestPresence_StoreLastSeenUpdated(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	initialTime := time.Now().Add(-1 * time.Hour)
	dev := &store.Device{
		ID:          "peer-device-002",
		Name:        "macbook-air",
		OS:          "darwin",
		LastSeen:    initialTime,
		LastAddress: "10.0.0.5:47820",
	}
	_ = st.Add(dev)

	cfg := config.Defaults()
	resolver := discovery.NewResolver(&cfg, st)
	pinger := &mockPinger{}

	pm := app.NewPresenceMonitorWithPinger(&cfg, st, pinger, resolver)
	pm.ProbeAll(context.Background())

	updated, ok := st.Get(dev.ID)
	if !ok {
		t.Fatal("failed to get device from store")
	}
	if !updated.LastSeen.After(initialTime) {
		t.Fatalf("LastSeen was not updated: %v <= %v", updated.LastSeen, initialTime)
	}
	if updated.LastAddress != "10.0.0.5:47820" {
		t.Fatalf("expected LastAddress '10.0.0.5:47820', got %q", updated.LastAddress)
	}
}

func TestPresence_UnresolvableAddress(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Device with no known address
	dev := &store.Device{
		ID:   "peer-unreachable",
		Name: "ghost-node",
		OS:   "linux",
	}
	_ = st.Add(dev)

	cfg := config.Defaults()
	resolver := discovery.NewResolver(&cfg, st)
	pinger := &mockPinger{}

	pm := app.NewPresenceMonitorWithPinger(&cfg, st, pinger, resolver)
	pm.ProbeAll(context.Background())

	if pm.IsOnline(dev.ID) {
		t.Fatal("unresolvable device should not be online")
	}
	if pinger.pingCount != 0 {
		t.Fatalf("expected 0 pings for unresolvable device, got %d", pinger.pingCount)
	}
}

func TestPresence_StartLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	st, _ := store.New(filepath.Join(tmpDir, "trusted_devices.json"))
	cfg := config.Defaults()
	resolver := discovery.NewResolver(&cfg, st)
	pinger := &mockPinger{}

	pm := app.NewPresenceMonitorWithPinger(&cfg, st, pinger, resolver)
	pm.SetInterval(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := pm.Start(ctx)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context error on stop, got %v", err)
	}
}
