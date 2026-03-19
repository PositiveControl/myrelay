package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PositiveControl/myrelay/pkg/bandwidth"
	"github.com/PositiveControl/myrelay/pkg/wireguard"
)

// InterfaceInfo holds state for a single managed WireGuard interface.
type InterfaceInfo struct {
	Name       string `json:"name"`
	ListenPort int    `json:"listen_port"`
	Address    string `json:"address"` // CIDR
	PublicKey  string `json:"public_key"`
	UserToken  string `json:"user_token"`
	Monitor    *bandwidth.Monitor `json:"-"`
}

// InterfaceManager orchestrates multiple WireGuard interfaces in managed mode.
type InterfaceManager struct {
	mu           sync.RWMutex
	interfaces   map[string]*InterfaceInfo
	tokenToIface map[string]string // reverse lookup: userToken → iface name
	adminToken   string
	pollInterval time.Duration
	statePath    string
}

// persistedState is the JSON-serializable form saved to disk.
type persistedState struct {
	Interfaces []persistedInterface `json:"interfaces"`
}

type persistedInterface struct {
	Name       string `json:"name"`
	ListenPort int    `json:"listen_port"`
	Address    string `json:"address"`
	PublicKey  string `json:"public_key"`
	UserToken  string `json:"user_token"`
}

// NewInterfaceManager creates a manager, loading persisted state if available.
func NewInterfaceManager(adminToken string, pollInterval time.Duration, statePath string) *InterfaceManager {
	mgr := &InterfaceManager{
		interfaces:   make(map[string]*InterfaceInfo),
		tokenToIface: make(map[string]string),
		adminToken:   adminToken,
		pollInterval: pollInterval,
		statePath:    statePath,
	}
	mgr.loadState()
	return mgr
}

// CreateInterface creates a new WireGuard interface and starts monitoring it.
func (m *InterfaceManager) CreateInterface(name string, listenPort int, address, userToken string) (*InterfaceInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.interfaces[name]; exists {
		return nil, fmt.Errorf("interface %s already exists", name)
	}
	if _, exists := m.tokenToIface[userToken]; exists {
		return nil, fmt.Errorf("user token already in use")
	}

	pubKey, err := wireguard.CreateInterface(name, listenPort, address)
	if err != nil {
		return nil, fmt.Errorf("create interface %s: %w", name, err)
	}

	mon := bandwidth.NewMonitor(name, m.pollInterval)
	mon.Start()

	info := &InterfaceInfo{
		Name:       name,
		ListenPort: listenPort,
		Address:    address,
		PublicKey:  pubKey,
		UserToken:  userToken,
		Monitor:    mon,
	}
	m.interfaces[name] = info
	m.tokenToIface[userToken] = name

	m.saveStateLocked()
	log.Printf("Created interface %s (port %d, address %s)", name, listenPort, address)
	return info, nil
}

// DestroyInterface tears down a WireGuard interface and removes it from management.
func (m *InterfaceManager) DestroyInterface(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, exists := m.interfaces[name]
	if !exists {
		return fmt.Errorf("interface %s not found", name)
	}

	info.Monitor.Stop()

	// Extract subnet from address for NAT cleanup.
	subnet := "0.0.0.0/0"
	if _, cidr, err := net.ParseCIDR(info.Address); err == nil {
		subnet = cidr.String()
	}

	if err := wireguard.DestroyInterface(name, subnet); err != nil {
		return fmt.Errorf("destroy interface %s: %w", name, err)
	}

	delete(m.tokenToIface, info.UserToken)
	delete(m.interfaces, name)
	m.saveStateLocked()
	log.Printf("Destroyed interface %s", name)
	return nil
}

// Get returns info for a single interface.
func (m *InterfaceManager) Get(name string) (*InterfaceInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.interfaces[name]
	return info, ok
}

// List returns all managed interfaces.
func (m *InterfaceManager) List() []*InterfaceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*InterfaceInfo, 0, len(m.interfaces))
	for _, info := range m.interfaces {
		result = append(result, info)
	}
	return result
}

// GetAllBandwidth returns bandwidth data keyed by interface name.
func (m *InterfaceManager) GetAllBandwidth() map[string][]bandwidth.PeerBandwidth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string][]bandwidth.PeerBandwidth, len(m.interfaces))
	for name, info := range m.interfaces {
		peers := info.Monitor.GetAllPeers()
		if len(peers) > 0 {
			result[name] = peers
		}
	}
	return result
}

// Authorize checks a token and returns the scope and interface name.
// Returns ("admin", "", true) for admin token, ("user", ifaceName, true) for user token.
func (m *InterfaceManager) Authorize(token string) (scope string, ifaceName string, ok bool) {
	if token == m.adminToken {
		return "admin", "", true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if name, exists := m.tokenToIface[token]; exists {
		return "user", name, true
	}
	return "", "", false
}

func (m *InterfaceManager) saveStateLocked() {
	if m.statePath == "" {
		return
	}
	state := persistedState{
		Interfaces: make([]persistedInterface, 0, len(m.interfaces)),
	}
	for _, info := range m.interfaces {
		state.Interfaces = append(state.Interfaces, persistedInterface{
			Name:       info.Name,
			ListenPort: info.ListenPort,
			Address:    info.Address,
			PublicKey:  info.PublicKey,
			UserToken:  info.UserToken,
		})
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal interface state: %v", err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(m.statePath), 0700); err != nil {
		log.Printf("Failed to create state directory: %v", err)
		return
	}
	if err := os.WriteFile(m.statePath, data, 0600); err != nil {
		log.Printf("Failed to save interface state: %v", err)
	}
}

func (m *InterfaceManager) loadState() {
	if m.statePath == "" {
		return
	}
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Failed to read interface state: %v", err)
		}
		return
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("Failed to parse interface state: %v", err)
		return
	}

	// Get currently running WireGuard interfaces for re-adoption.
	running := make(map[string]bool)
	if ifaces, err := wireguard.ListInterfaces(); err == nil {
		for _, name := range ifaces {
			running[name] = true
		}
	}

	for _, pi := range state.Interfaces {
		if !running[pi.Name] {
			log.Printf("Interface %s from state file is not running, skipping", pi.Name)
			continue
		}

		// Re-read the public key from the live interface.
		pubKey, err := wireguard.ReadServerPublicKey(pi.Name)
		if err != nil {
			log.Printf("Failed to read public key for %s, skipping: %v", pi.Name, err)
			continue
		}

		mon := bandwidth.NewMonitor(pi.Name, m.pollInterval)
		mon.Start()

		m.interfaces[pi.Name] = &InterfaceInfo{
			Name:       pi.Name,
			ListenPort: pi.ListenPort,
			Address:    pi.Address,
			PublicKey:  pubKey,
			UserToken:  pi.UserToken,
			Monitor:    mon,
		}
		if pi.UserToken != "" {
			m.tokenToIface[pi.UserToken] = pi.Name
		}
		log.Printf("Re-adopted interface %s from persisted state", pi.Name)
	}
}
