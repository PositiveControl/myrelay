package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client communicates with VPN node agents to manage WireGuard peers.
type Client struct {
	httpClient *http.Client
	// nodeAgents maps node ID -> agent base URL (e.g., "http://5.78.83.247:8081")
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

// RegisterNode stores the agent URL and token for a node.
func (c *Client) RegisterNode(nodeID, agentURL, token string) {
	c.nodeAgents[nodeID] = agentURL
	c.nodeTokens[nodeID] = token
}

// AddPeer tells the node's agent to add a WireGuard peer.
func (c *Client) AddPeer(nodeID, publicKey, allowedIPs string) error {
	agentURL, ok := c.nodeAgents[nodeID]
	if !ok {
		return fmt.Errorf("no agent registered for node %s", nodeID)
	}

	payload, _ := json.Marshal(map[string]string{
		"public_key": publicKey,
		"allowed_ips": allowedIPs,
	})

	req, err := http.NewRequest("POST", agentURL+"/peers", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token, ok := c.nodeTokens[nodeID]; ok && token != "" {
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
	agentURL, ok := c.nodeAgents[nodeID]
	if !ok {
		return fmt.Errorf("no agent registered for node %s", nodeID)
	}

	payload, _ := json.Marshal(map[string]string{
		"public_key": publicKey,
	})

	req, err := http.NewRequest("POST", agentURL+"/peers/remove", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token, ok := c.nodeTokens[nodeID]; ok && token != "" {
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
