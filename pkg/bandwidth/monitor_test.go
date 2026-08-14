package bandwidth

import (
	"io"
	"log"
	"sync"
	"testing"
	"time"
)

// testInterval is long enough that the ticker never fires during a test, so
// only the initial poll in loop() can run.
const testInterval = time.Hour

// quietLogs silences the monitor's poll errors. readTransfer shells out to
// `wg`, which is absent on developer machines; the resulting log line is noise,
// not a failure.
func quietLogs(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

// waitForExit fails the test unless the polling goroutine has returned.
func waitForExit(t *testing.T, m *Monitor) {
	t.Helper()
	select {
	case <-m.done:
	case <-time.After(2 * time.Second):
		t.Fatal("polling goroutine did not exit after Stop")
	}
}

func TestMonitorStop_Idempotent(t *testing.T) {
	quietLogs(t)

	m := NewMonitor("wg-test", testInterval)
	m.Start()

	// A failed teardown leaves the interface registered, so the control plane
	// retries the destroy — Stop lands more than once.
	m.Stop()
	m.Stop()
	m.Stop()

	waitForExit(t, m)
}

func TestMonitorStop_Concurrent(t *testing.T) {
	quietLogs(t)

	m := NewMonitor("wg-test", testInterval)
	m.Start()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Stop()
		}()
	}
	wg.Wait()

	waitForExit(t, m)
}

func TestMonitorStop_BeforeStart(t *testing.T) {
	quietLogs(t)

	m := NewMonitor("wg-test", testInterval)
	m.Stop()
	m.Start()

	waitForExit(t, m)

	// The loop bailed before polling, so no peer data was ever collected.
	if peers := m.GetAllPeers(); len(peers) != 0 {
		t.Fatalf("expected no peers after stop-before-start, got %d", len(peers))
	}
}

func TestMonitorStop_WithoutStart(t *testing.T) {
	m := NewMonitor("wg-test", testInterval)

	// CreateInterface can fail between NewMonitor and Start; Stop must not
	// panic on a monitor whose goroutine never ran.
	m.Stop()
	m.Stop()
}

func TestMonitorGetAllPeers_AfterStop(t *testing.T) {
	quietLogs(t)

	m := NewMonitor("wg-test", testInterval)
	m.Start()
	m.Stop()
	waitForExit(t, m)

	peers := m.GetAllPeers()
	if peers == nil {
		t.Fatal("GetAllPeers returned nil, want an empty slice")
	}
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}
}

func TestMonitorGetPeer_AfterStop(t *testing.T) {
	quietLogs(t)

	m := NewMonitor("wg-test", testInterval)
	m.Start()
	m.Stop()
	waitForExit(t, m)

	if _, ok := m.GetPeer("nonexistent"); ok {
		t.Fatal("GetPeer reported a peer that was never recorded")
	}
}
