package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/m7s/vpn/internal/agent"
	"github.com/m7s/vpn/internal/bypass"
	"github.com/m7s/vpn/internal/db"
	"github.com/m7s/vpn/internal/httputil"
	"github.com/m7s/vpn/internal/models"
	"github.com/m7s/vpn/internal/wireguard"
)

// UserHandler handles HTTP requests for user management.
type UserHandler struct {
	db     *db.DB
	agents *agent.Client
}

// NewUserHandler creates a handler backed by the database.
func NewUserHandler(database *db.DB, agents *agent.Client) *UserHandler {
	return &UserHandler{db: database, agents: agents}
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
	node, err := h.assignNode(req.NodeID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to query nodes")
		return
	}
	if node == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "no available nodes")
		return
	}
	user.AssignedNodeID = node.ID

	// Assign an IP address.
	nextIP, err := h.db.NextIP()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to allocate IP")
		return
	}
	ip := fmt.Sprintf("10.0.0.%d", nextIP)
	user.Address = ip + "/32"

	// Push peer to the node's WireGuard interface via the agent.
	if err := h.agents.AddPeer(node.ID, keys.PublicKey, user.Address); err != nil {
		log.Printf("Failed to push peer to node %s: %v", node.ID, err)
		httputil.WriteError(w, http.StatusBadGateway, "failed to configure VPN node: "+err.Error())
		return
	}

	// Save to database.
	if err := h.db.CreateUser(user); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to save user")
		return
	}
	if err := h.db.IncrementNodePeers(node.ID); err != nil {
		log.Printf("Failed to increment peer count for node %s: %v", node.ID, err)
	}

	// Compute AllowedIPs based on plan defaults (new user has no override).
	allowedIPs, err := bypass.ComputeAllowedIPsForUser(user.Plan, nil)
	if err != nil {
		log.Printf("Failed to compute AllowedIPs: %v", err)
		allowedIPs = "0.0.0.0/0" // fallback to full tunnel
	}

	// Generate client config.
	clientConfig, err := wireguard.GeneratePeerConfig(wireguard.PeerConfig{
		PrivateKey: keys.PrivateKey,
		Address:    ip + "/24",
		DNS:        "1.1.1.1, 8.8.8.8",
		PublicKey:  node.PublicKey,
		Endpoint:   node.WireGuardEndpoint(),
		AllowedIPs: allowedIPs,
	})
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate client config")
		return
	}

	// Generate onboarding token.
	onboardToken, err := generateOnboardingToken()
	if err != nil {
		log.Printf("Failed to generate onboarding token: %v", err)
	}
	var onboardingURL string
	if onboardToken != "" {
		expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)
		if err := h.db.CreateOnboardingToken(user.ID, onboardToken, expiresAt); err != nil {
			log.Printf("Failed to save onboarding token: %v", err)
			onboardToken = ""
		} else {
			onboardingURL = "/onboard/" + onboardToken
		}
	}

	resp := map[string]any{
		"user":          user,
		"client_config": clientConfig,
	}
	if onboardingURL != "" {
		resp["onboarding_url"] = onboardingURL
	}
	httputil.WriteJSON(w, http.StatusCreated, resp)
}

// List handles GET /api/users.
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	users, err := h.db.ListUsers()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	if users == nil {
		users = []*models.User{}
	}
	httputil.WriteJSON(w, http.StatusOK, users)
}

// Get handles GET /api/users/{id}.
func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := h.db.GetUser(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, user)
}

// Delete handles DELETE /api/users/{id}.
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	user, err := h.db.DeleteUser(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	if err := h.db.DecrementNodePeers(user.AssignedNodeID); err != nil {
		log.Printf("Failed to decrement peer count for node %s: %v", user.AssignedNodeID, err)
	}

	// Remove peer from the node.
	if err := h.agents.RemovePeer(user.AssignedNodeID, user.PublicKey); err != nil {
		log.Printf("Failed to remove peer from node %s: %v", user.AssignedNodeID, err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// assignNode picks the best available node.
func (h *UserHandler) assignNode(nodeID string) (*models.Node, error) {
	if nodeID != "" {
		node, err := h.db.GetNode(nodeID)
		if err != nil {
			return nil, err
		}
		if node != nil && node.HasCapacity() {
			return node, nil
		}
		return nil, nil
	}

	nodes, err := h.db.ListNodes()
	if err != nil {
		return nil, err
	}
	var best *models.Node
	for _, n := range nodes {
		if !n.HasCapacity() {
			continue
		}
		if best == nil || n.CurrentPeers < best.CurrentPeers {
			best = n
		}
	}
	return best, nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateOnboardingToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
