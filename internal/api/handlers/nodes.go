package handlers

import (
	"net/http"
	"sync"

	"github.com/m7s/vpn/internal/httputil"
	"github.com/m7s/vpn/internal/models"
)

// NodeHandler handles HTTP requests for VPN node management.
type NodeHandler struct {
	mu    sync.RWMutex
	nodes map[string]*models.Node
}

// NewNodeHandler creates a handler backed by the given node map.
func NewNodeHandler(nodes map[string]*models.Node) *NodeHandler {
	return &NodeHandler{nodes: nodes}
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
// In a full implementation this would push the latest WireGuard config to the node agent.
// For now it returns the node's current state and marks it as a sync acknowledgment.
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
