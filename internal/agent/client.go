package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/PositiveControl/myrelay/internal/security"
)

// Client communicates with VPN node agents to manage WireGuard peers.
type Client struct {
	httpClient *http.Client
	mu         sync.RWMutex
	// nodeAgents maps node ID -> agent base URL (e.g., "https://203.0.113.1:8081")
	nodeAgents map[string]string
	// nodeTokens maps node ID -> agent token
	nodeTokens map[string]string
}

// NewClient creates a new agent client.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		nodeAgents: make(map[string]string),
		nodeTokens: make(map[string]string),
	}
}

// SetTLSConfig configures the client to use TLS for agent communication.
func (c *Client) SetTLSConfig(tlsConfig *tls.Config) {
	c.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
}

// RegisterNode stores the agent URL and token for a node.
func (c *Client) RegisterNode(nodeID, agentURL, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodeAgents[nodeID] = agentURL
	c.nodeTokens[nodeID] = token
}

func (c *Client) getNodeConn(nodeID string) (string, string, error) {
	c.mu.RLock()
	agentURL, ok := c.nodeAgents[nodeID]
	token := c.nodeTokens[nodeID]
	c.mu.RUnlock()
	if !ok {
		return "", "", fmt.Errorf("no agent registered for node %s", nodeID)
	}
	return agentURL, token, nil
}

// AddPeer tells the node's agent to add a WireGuard peer.
func (c *Client) AddPeer(nodeID, publicKey, allowedIPs string) error {
	agentURL, token, err := c.getNodeConn(nodeID)
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]string{
		"public_key":  publicKey,
		"allowed_ips": allowedIPs,
	})

	req, err := http.NewRequest("POST", agentURL+"/peers", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("agent returned status %d", resp.StatusCode)
	}
	return nil
}

// RemovePeer tells the node's agent to remove a WireGuard peer.
func (c *Client) RemovePeer(nodeID, publicKey string) error {
	agentURL, token, err := c.getNodeConn(nodeID)
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]string{
		"public_key": publicKey,
	})

	req, err := http.NewRequest("POST", agentURL+"/peers/remove", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("agent returned status %d", resp.StatusCode)
	}
	return nil
}

// GetSecurity retrieves the security hardening status from a node's agent.
func (c *Client) GetSecurity(nodeID string) (*security.Status, error) {
	agentURL, token, err := c.getNodeConn(nodeID)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", agentURL+"/security", nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("agent returned status %d: %s", resp.StatusCode, string(body))
	}

	var status security.Status
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode security status: %w", err)
	}
	return &status, nil
}
