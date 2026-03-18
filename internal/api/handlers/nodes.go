package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/PositiveControl/myrelay/internal/agent"
	"github.com/PositiveControl/myrelay/internal/bandwidth"
	"github.com/PositiveControl/myrelay/internal/db"
	"github.com/PositiveControl/myrelay/internal/httputil"
	"github.com/PositiveControl/myrelay/internal/models"
)

// TokenGenerator generates authentication tokens for nodes.
type TokenGenerator interface {
	GenerateNodeToken(nodeID string) (string, error)
}

// NodeHandler handles HTTP requests for VPN node management.
type NodeHandler struct {
	db       *db.DB
	tokenGen TokenGenerator
	agents   *agent.Client
	useTLS   bool

	mu            sync.RWMutex
	bandwidthData map[string][]bandwidth.PeerBandwidth // still in-memory, not critical to persist
}

// NewNodeHandler creates a handler backed by the database.
func NewNodeHandler(database *db.DB, tokenGen TokenGenerator, agents *agent.Client) *NodeHandler {
	return &NodeHandler{db: database, tokenGen: tokenGen, agents: agents}
}

// SetUseTLS configures the handler to generate https:// agent URLs.
func (h *NodeHandler) SetUseTLS(useTLS bool) {
	h.useTLS = useTLS
}

// List handles GET /api/nodes.
func (h *NodeHandler) List(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.db.ListNodes()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to list nodes")
		return
	}
	if nodes == nil {
		nodes = []*models.Node{}
	}
	httputil.WriteJSON(w, http.StatusOK, nodes)
}

// Get handles GET /api/nodes/{id}.
func (h *NodeHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := h.db.GetNode(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if node == nil {
		httputil.WriteError(w, http.StatusNotFound, "node not found")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, node)
}

// Sync handles POST /api/nodes/{id}/sync.
func (h *NodeHandler) Sync(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := h.db.GetNode(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if node == nil {
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

	// Save node and token to database.
	if err := h.db.CreateNode(&node); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to save node: "+err.Error())
		return
	}
	if err := h.db.SaveNodeToken(node.ID, agentToken); err != nil {
		log.Printf("Failed to save node token: %v", err)
	}

	// Register the agent URL so the control plane can push peers to it.
	scheme := "http"
	if h.useTLS {
		scheme = "https"
	}
	agentURL := fmt.Sprintf("%s://%s:8081", scheme, node.IP)
	h.agents.RegisterNode(node.ID, agentURL, agentToken)

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

	node, err := h.db.GetNode(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if node == nil {
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

// GetSecurity handles GET /api/nodes/{id}/security.
func (h *NodeHandler) GetSecurity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	node, err := h.db.GetNode(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if node == nil {
		httputil.WriteError(w, http.StatusNotFound, "node not found")
		return
	}

	status, err := h.agents.GetSecurity(id)
	if err != nil {
		log.Printf("Failed to get security status for node %s: %v", id, err)
		httputil.WriteError(w, http.StatusBadGateway, "failed to reach node agent")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, status)
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
