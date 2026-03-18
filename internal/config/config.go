package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultPath is the default location for the peer config file.
const DefaultPath = "/etc/vpn/peers.json"

// ServerInfo holds the WireGuard server (node) configuration.
type ServerInfo struct {
	Interface  string `json:"interface"`
	PublicKey  string `json:"public_key"`
	Endpoint   string `json:"endpoint"`
	Address    string `json:"address"`
	DNS        string `json:"dns"`
	ListenPort int    `json:"listen_port"`
}

// Peer represents a configured WireGuard peer.
type Peer struct {
	Name       string    `json:"name"`
	PublicKey  string    `json:"public_key"`
	AllowedIPs string   `json:"allowed_ips"`
	CreatedAt  time.Time `json:"created_at"`
}

// Config is the local peer configuration file used in standalone mode.
// It is the source of truth for which peers are configured on the node.
// The CLI writes to it; the agent watches it and syncs WireGuard.
type Config struct {
	Server ServerInfo `json:"server"`
	NextIP int        `json:"next_ip"`
	Peers  []Peer     `json:"peers"`

	path string
	mu   sync.Mutex
}

// Load reads a config from disk. If the file doesn't exist, returns a
// default config that will be saved to the given path.
func Load(path string) (*Config, error) {
	c := &Config{
		path:   path,
		NextIP: 2, // 10.0.0.1 is the server, peers start at .2
		Server: ServerInfo{
			Interface:  "wg0",
			Address:    "10.0.0.1/24",
			DNS:        "1.1.1.1, 8.8.8.8",
			ListenPort: 51820,
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.path = path
	return c, nil
}

// Save writes the config to disk atomically (write tmp + rename).
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

func (c *Config) saveLocked() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename config: %w", err)
	}
	return nil
}

// Path returns the file path of this config.
func (c *Config) Path() string {
	return c.path
}

// AddPeer adds a new peer, allocates an IP, saves, and returns the peer
// and its allocated address (e.g., "10.0.0.2/32").
func (c *Config) AddPeer(name, publicKey string) (*Peer, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check for duplicate name.
	for _, p := range c.Peers {
		if p.Name == name {
			return nil, "", fmt.Errorf("peer %q already exists", name)
		}
	}

	// Check for duplicate public key.
	for _, p := range c.Peers {
		if p.PublicKey == publicKey {
			return nil, "", fmt.Errorf("public key already in use by peer %q", p.Name)
		}
	}

	if c.NextIP > 254 {
		return nil, "", fmt.Errorf("no more IPs available in 10.0.0.0/24")
	}

	address := fmt.Sprintf("10.0.0.%d/32", c.NextIP)
	peer := Peer{
		Name:       name,
		PublicKey:  publicKey,
		AllowedIPs: address,
		CreatedAt:  time.Now().UTC(),
	}
	c.Peers = append(c.Peers, peer)
	c.NextIP++

	if err := c.saveLocked(); err != nil {
		// Rollback.
		c.Peers = c.Peers[:len(c.Peers)-1]
		c.NextIP--
		return nil, "", err
	}
	return &peer, address, nil
}

// RemovePeer removes a peer by name and saves.
func (c *Config) RemovePeer(name string) (*Peer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, p := range c.Peers {
		if p.Name == name {
			removed := p
			c.Peers = append(c.Peers[:i], c.Peers[i+1:]...)
			if err := c.saveLocked(); err != nil {
				// Rollback.
				c.Peers = append(c.Peers[:i], append([]Peer{removed}, c.Peers[i:]...)...)
				return nil, err
			}
			return &removed, nil
		}
	}
	return nil, fmt.Errorf("peer %q not found", name)
}

// GetPeer returns a peer by name, or nil if not found.
func (c *Config) GetPeer(name string) *Peer {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, p := range c.Peers {
		if p.Name == name {
			copy := p
			return &copy
		}
	}
	return nil
}

// ListPeers returns a copy of all peers.
func (c *Config) ListPeers() []Peer {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make([]Peer, len(c.Peers))
	copy(result, c.Peers)
	return result
}

// Reload re-reads the config from disk, returning true if it changed.
func (c *Config) Reload() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.path)
	if err != nil {
		return false, fmt.Errorf("read config: %w", err)
	}

	var fresh Config
	if err := json.Unmarshal(data, &fresh); err != nil {
		return false, fmt.Errorf("parse config: %w", err)
	}

	// Quick change detection: compare peer count and public keys.
	changed := len(fresh.Peers) != len(c.Peers)
	if !changed {
		existing := make(map[string]bool, len(c.Peers))
		for _, p := range c.Peers {
			existing[p.PublicKey] = true
		}
		for _, p := range fresh.Peers {
			if !existing[p.PublicKey] {
				changed = true
				break
			}
		}
	}

	c.Server = fresh.Server
	c.NextIP = fresh.NextIP
	c.Peers = fresh.Peers
	return changed, nil
}
