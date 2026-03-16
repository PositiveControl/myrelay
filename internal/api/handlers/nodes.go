package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/m7s/vpn/internal/agent"
	"github.com/m7s/vpn/internal/bandwidth"
	"github.com/m7s/vpn/internal/httputil"
	"github.com/m7s/vpn/internal/models"
)

// TokenGenerator generates authentication tokens for nodes.
type TokenGenerator interface {
	GenerateNodeToken(nodeID string) (string, error)
}

// NodeHandler handles HTTP requests for VPN node management.
type NodeHandler struct {
	mu            sync.RWMutex
	nodes         map[string]*models.Node
	bandwidthData map[string][]bandwidth.PeerBandwidth
	tokenGen      TokenGenerator
	agents        *agent.Client
}

// NewNodeHandler creates a handler backed by the given node map.
func NewNodeHandler(nodes map[string]*models.Node, tokenGen TokenGenerator, agents *agent.Client) *NodeHandler {
	return &NodeHandler{nodes: nodes, tokenGen: tokenGen, agents: agents}
}

// List handles GET /api/nodes.
func (h *NodeHandler) List(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	nodes := make([]*models.Node, 0, len(h.nodes))
	for _, n := range h.nodes {
		nodes = append(nodes, n)
	}
	httputil.WriteJSON(w, http.StatusOK, nodes)
}

// Get handles GET /api/nodes/{id}.
func (h *NodeHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.RLock()
	node, ok := h.nodes[id]
	h.mu.RUnlock()

	if !ok {
		httputil.WriteError(w, http.StatusNotFound, "node not found")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, node)
}

// Sync handles POST /api/nodes/{id}/sync.
func (h *NodeHandler) Sync(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.RLock()
	node, ok := h.nodes[id]
	h.mu.RUnlock()

	if !ok {
		httputil.WriteError(w, http.StatusNotFound, "node not found")
		return
	}

	if node.Status != models.NodeStatusActive {
		httputil.WriteError(w, http.StatusConflict, "node is not active")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"node":   node,
		"synced": true,
	})
}

// Register handles POST /api/nodes — registers a new node and returns its agent token.
func (h *NodeHandler) Register(w http.ResponseWriter, r *http.Request) {
	var node models.Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if node.ID == "" || node.Name == "" || node.IP == "" {
		httputil.WriteError(w, http.StatusBadRequest, "id, name, and ip are required")
		return
	}
	if node.MaxPeers == 0 {
		node.MaxPeers = 50
	}
	if node.Status == "" {
		node.Status = models.NodeStatusActive
	}

	// Generate a per-node agent token.
	agentToken, err := h.tokenGen.GenerateNodeToken(node.ID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate node token")
		return
	}

	// Register the agent URL so the control plane can push peers to it.
	agentURL := fmt.Sprintf("http://%s:8081", node.IP)
	h.agents.RegisterNode(node.ID, agentURL, agentToken)

	h.mu.Lock()
	h.nodes[node.ID] = &node
	h.mu.Unlock()

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{
		"node":        node,
		"agent_token": agentToken,
	})
}

// bandwidthReport is the JSON body sent by the node agent.
type bandwidthReport struct {
	NodeID string                    `json:"node_id"`
	Peers  []bandwidth.PeerBandwidth `json:"peers"`
}

// ReportBandwidth handles POST /api/nodes/{id}/bandwidth.
func (h *NodeHandler) ReportBandwidth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.RLock()
	_, ok := h.nodes[id]
	h.mu.RUnlock()

	if !ok {
		httputil.WriteError(w, http.StatusNotFound, "node not found")
		return
	}

	var report bandwidthReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.mu.Lock()
	if h.bandwidthData == nil {
		h.bandwidthData = make(map[string][]bandwidth.PeerBandwidth)
	}
	h.bandwidthData[id] = report.Peers
	h.mu.Unlock()

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"accepted": len(report.Peers),
	})
}

// GetBandwidth handles GET /api/nodes/{id}/bandwidth.
func (h *NodeHandler) GetBandwidth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.RLock()
	peers := h.bandwidthData[id]
	h.mu.RUnlock()

	if peers == nil {
		peers = []bandwidth.PeerBandwidth{}
	}
	httputil.WriteJSON(w, http.StatusOK, peers)
}
