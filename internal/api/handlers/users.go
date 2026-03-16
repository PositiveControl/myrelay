package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/m7s/vpn/internal/agent"
	"github.com/m7s/vpn/internal/httputil"
	"github.com/m7s/vpn/internal/models"
	"github.com/m7s/vpn/internal/wireguard"
)

// UserHandler handles HTTP requests for user management.
type UserHandler struct {
	mu      sync.RWMutex
	users   map[string]*models.User
	nodes   map[string]*models.Node
	agents  *agent.Client
	nextIP  uint32
}

// NewUserHandler creates a handler backed by the given user and node maps.
func NewUserHandler(users map[string]*models.User, nodes map[string]*models.Node, agents *agent.Client) *UserHandler {
	return &UserHandler{users: users, nodes: nodes, agents: agents, nextIP: 2}
}

// createUserRequest is the JSON body for creating a new user.
type createUserRequest struct {
	Email  string      `json:"email"`
	Plan   models.Plan `json:"plan"`
	NodeID string      `json:"node_id"`
}

// Create handles POST /api/users.
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		httputil.WriteError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Plan == "" {
		req.Plan = models.PlanStandard
	}
	if req.Plan != models.PlanStandard && req.Plan != models.PlanPremium {
		httputil.WriteError(w, http.StatusBadRequest, "plan must be 'standard' or 'premium'")
		return
	}

	id, err := generateID()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate ID")
		return
	}

	user := models.NewUser(id, req.Email, req.Plan)

	// Generate WireGuard keys for the user.
	keys, err := wireguard.GenerateKeyPair()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate WireGuard keys")
		return
	}
	user.PublicKey = keys.PublicKey
	user.PrivateKey = keys.PrivateKey

	// Assign to a node.
	node := h.assignNode(req.NodeID)
	if node == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "no available nodes")
		return
	}
	user.AssignedNodeID = node.ID

	// Assign an IP address in the 10.0.0.x range.
	ip := fmt.Sprintf("10.0.0.%d", h.nextIP)
	h.nextIP++
	user.Address = ip + "/32"

	// Push peer to the node's WireGuard interface via the agent.
	if err := h.agents.AddPeer(node.ID, keys.PublicKey, user.Address); err != nil {
		log.Printf("Failed to push peer to node %s: %v", node.ID, err)
		httputil.WriteError(w, http.StatusBadGateway, "failed to configure VPN node: "+err.Error())
		return
	}

	h.mu.Lock()
	h.users[user.ID] = user
	node.CurrentPeers++
	h.mu.Unlock()

	// Generate client config.
	clientConfig, err := wireguard.GeneratePeerConfig(wireguard.PeerConfig{
		PrivateKey: keys.PrivateKey,
		Address:    ip + "/24",
		DNS:        "1.1.1.1, 8.8.8.8",
		PublicKey:  node.PublicKey,
		Endpoint:   node.WireGuardEndpoint(),
		AllowedIPs: "0.0.0.0/0",
	})
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate client config")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{
		"user":          user,
		"client_config": clientConfig,
	})
}

// List handles GET /api/users.
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	users := make([]*models.User, 0, len(h.users))
	for _, u := range h.users {
		users = append(users, u)
	}
	httputil.WriteJSON(w, http.StatusOK, users)
}

// Get handles GET /api/users/{id}.
func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.RLock()
	user, ok := h.users[id]
	h.mu.RUnlock()

	if !ok {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, user)
}

// Delete handles DELETE /api/users/{id}.
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.mu.Lock()
	user, ok := h.users[id]
	if !ok {
		h.mu.Unlock()
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	nodeID := user.AssignedNodeID
	publicKey := user.PublicKey
	delete(h.users, id)

	if node, ok := h.nodes[nodeID]; ok && node.CurrentPeers > 0 {
		node.CurrentPeers--
	}
	h.mu.Unlock()

	// Remove peer from the node.
	if err := h.agents.RemovePeer(nodeID, publicKey); err != nil {
		log.Printf("Failed to remove peer from node %s: %v", nodeID, err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// assignNode picks the best available node for a new user.
func (h *UserHandler) assignNode(nodeID string) *models.Node {
	if nodeID != "" {
		if node, ok := h.nodes[nodeID]; ok && node.HasCapacity() {
			return node
		}
		return nil
	}
	var best *models.Node
	for _, n := range h.nodes {
		if !n.HasCapacity() {
			continue
		}
		if best == nil || n.CurrentPeers < best.CurrentPeers {
			best = n
		}
	}
	return best
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
