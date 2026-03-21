package bandwidth

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/PositiveControl/myrelay/pkg/wireguard"
)

// PeerBandwidth tracks cumulative and delta bandwidth for a single peer.
type PeerBandwidth struct {
	PublicKey         string `json:"public_key"`
	TotalReceived    int64  `json:"total_received"`
	TotalSent        int64  `json:"total_sent"`
	IntervalReceived int64  `json:"interval_received"`
	IntervalSent     int64  `json:"interval_sent"`
	LastUpdated      time.Time `json:"last_updated"`
}

// Monitor periodically polls `wg show <interface> transfer` and tracks
// per-peer bandwidth usage deltas.
type Monitor struct {
	interfaceName string
	interval      time.Duration

	mu       sync.RWMutex
	peers    map[string]*PeerBandwidth // keyed by public key
	previous map[string]wireguard.PeerTransfer

	stopCh chan struct{}
}

// NewMonitor creates a bandwidth monitor for the given WireGuard interface.
func NewMonitor(interfaceName string, pollInterval time.Duration) *Monitor {
	return &Monitor{
		interfaceName: interfaceName,
		interval:      pollInterval,
		peers:         make(map[string]*PeerBandwidth),
		previous:      make(map[string]wireguard.PeerTransfer),
		stopCh:        make(chan struct{}),
	}
}

// Start begins the polling loop in a background goroutine.
func (m *Monitor) Start() {
	go m.loop()
}

// Stop signals the polling loop to exit.
func (m *Monitor) Stop() {
	close(m.stopCh)
}

// GetAllPeers returns a snapshot of bandwidth data for all known peers.
func (m *Monitor) GetAllPeers() []PeerBandwidth {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]PeerBandwidth, 0, len(m.peers))
	for _, pb := range m.peers {
		result = append(result, *pb)
	}
	return result
}

// GetPeer returns bandwidth data for a specific peer public key.
func (m *Monitor) GetPeer(publicKey string) (*PeerBandwidth, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pb, ok := m.peers[publicKey]
	if !ok {
		return nil, false
	}
	copy := *pb
	return &copy, true
}

func (m *Monitor) loop() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	// Do an initial poll immediately.
	m.poll()

	for {
		select {
		case <-ticker.C:
			m.poll()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Monitor) poll() {
	output, err := m.readTransfer()
	if err != nil {
		log.Printf("bandwidth: failed to read wg transfer: %v", err)
		return
	}

	transfers, err := wireguard.ParseWgShow(output)
	if err != nil {
		log.Printf("bandwidth: failed to parse wg output: %v", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, t := range transfers {
		prev, hasPrev := m.previous[t.PublicKey]

		var deltaRecv, deltaSent int64
		if hasPrev {
			deltaRecv = t.BytesReceived - prev.BytesReceived
			deltaSent = t.BytesSent - prev.BytesSent
			// Handle counter reset (e.g. interface restart):
			// WireGuard resets to zero, so delta goes negative.
			// Use the current value as the delta (traffic since reset).
			if deltaRecv < 0 {
				deltaRecv = t.BytesReceived
			}
			if deltaSent < 0 {
				deltaSent = t.BytesSent
			}
		}

		pb, exists := m.peers[t.PublicKey]
		if !exists {
			pb = &PeerBandwidth{PublicKey: t.PublicKey}
			m.peers[t.PublicKey] = pb
		}

		// Accumulate deltas into cumulative totals so they survive
		// interface restarts (which reset WireGuard counters to zero).
		pb.TotalReceived += deltaRecv
		pb.TotalSent += deltaSent
		pb.IntervalReceived = deltaRecv
		pb.IntervalSent = deltaSent
		pb.LastUpdated = now

		m.previous[t.PublicKey] = t
	}
}

func (m *Monitor) readTransfer() (string, error) {
	cmd := exec.Command("wg", "show", m.interfaceName, "transfer")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("exec wg show %s transfer: %w", m.interfaceName, err)
	}
	return string(out), nil
}
