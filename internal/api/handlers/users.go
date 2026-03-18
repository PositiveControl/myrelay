package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PositiveControl/myrelay/internal/agent"
	"github.com/PositiveControl/myrelay/internal/db"
	"github.com/PositiveControl/myrelay/internal/httputil"
	"github.com/PositiveControl/myrelay/internal/models"
	"github.com/PositiveControl/myrelay/internal/validate"
	"github.com/PositiveControl/myrelay/internal/wireguard"
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
	Email     string      `json:"email"`
	Plan      models.Plan `json:"plan"`
	NodeID    string      `json:"node_id"`
	PublicKey string      `json:"public_key"` // Client-provided public key (recommended for security)
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

	// Use client-provided public key if available (preferred: server never sees private key).
	// Fall back to server-side generation for backward compatibility.
	if req.PublicKey != "" {
		if err := validate.WireGuardKey(req.PublicKey); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid public_key: "+err.Error())
			return
		}
		user.PublicKey = req.PublicKey
		// Private key stays empty — client holds it.
	} else {
		keys, err := wireguard.GenerateKeyPair()
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "failed to generate WireGuard keys")
			return
		}
		user.PublicKey = keys.PublicKey
		user.PrivateKey = keys.PrivateKey
		log.Printf("Warning: server-side key generation used for user %s — client-side key generation is recommended", req.Email)
	}

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
	if err := h.agents.AddPeer(node.ID, user.PublicKey, user.Address); err != nil {
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

	// Generate client config (only if server holds the private key — backward compat).
	var clientConfig string
	if user.PrivateKey != "" {
		cfg, err := wireguard.GeneratePeerConfig(wireguard.PeerConfig{
			PrivateKey: user.PrivateKey,
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
		clientConfig = cfg
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
		"user": user,
	}
	if clientConfig != "" {
		resp["client_config"] = clientConfig
	}
	if onboardingURL != "" {
		resp["onboarding_url"] = onboardingURL
	}
	// When client-side keys are used, include server info so the client
	// can build its own config.
	if user.PrivateKey == "" {
		resp["server_public_key"] = node.PublicKey
		resp["server_endpoint"] = node.WireGuardEndpoint()
		resp["assigned_address"] = user.Address
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

// ListRules handles GET /api/users/{id}/rules.
func (h *UserHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	user, err := h.db.GetUser(userID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	rules, err := h.db.ListNetworkRules(userID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to list rules")
		return
	}
	if rules == nil {
		rules = []*models.NetworkRule{}
	}
	httputil.WriteJSON(w, http.StatusOK, rules)
}

// createRuleRequest is the JSON body for adding a network rule.
type createRuleRequest struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Action  string `json:"action"`
}

// AddRule handles POST /api/users/{id}/rules.
func (h *UserHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	user, err := h.db.GetUser(userID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	var req createRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Network == "" {
		httputil.WriteError(w, http.StatusBadRequest, "network is required (CIDR notation)")
		return
	}
	if req.Action == "" {
		req.Action = "bypass"
	}
	if req.Action != "bypass" {
		httputil.WriteError(w, http.StatusBadRequest, "action must be 'bypass'")
		return
	}

	// Validate CIDR
	if _, _, err := net.ParseCIDR(req.Network); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid CIDR notation: "+err.Error())
		return
	}

	id, err := generateID()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate ID")
		return
	}

	rule := &models.NetworkRule{
		ID:      id,
		UserID:  userID,
		Name:    req.Name,
		Network: req.Network,
		Action:  req.Action,
	}
	if err := h.db.CreateNetworkRule(rule); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to save rule")
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, rule)
}

// RemoveRule handles DELETE /api/users/{id}/rules/{ruleId}.
func (h *UserHandler) RemoveRule(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	ruleID := r.PathValue("ruleId")

	rule, err := h.db.GetNetworkRule(ruleID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if rule == nil || rule.UserID != userID {
		httputil.WriteError(w, http.StatusNotFound, "rule not found")
		return
	}

	if err := h.db.DeleteNetworkRule(ruleID); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to delete rule")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Config handles GET /api/users/{id}/config — regenerates WireGuard client config with rules applied.
func (h *UserHandler) Config(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	user, err := h.db.GetUser(userID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	node, err := h.db.GetNode(user.AssignedNodeID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if node == nil {
		httputil.WriteError(w, http.StatusInternalServerError, "assigned node not found")
		return
	}

	// Fetch bypass rules and compute AllowedIPs
	rules, err := h.db.ListNetworkRules(userID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to list rules")
		return
	}

	var excludedCIDRs []string
	for _, rule := range rules {
		if rule.Action == "bypass" {
			excludedCIDRs = append(excludedCIDRs, rule.Network)
		}
	}

	allowedIPs, err := wireguard.ComputeAllowedIPs(excludedCIDRs)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to compute AllowedIPs: "+err.Error())
		return
	}

	// Use /24 for client address (matching existing Create handler behavior)
	address := user.Address
	if strings.HasSuffix(address, "/32") {
		address = strings.TrimSuffix(address, "/32") + "/24"
	}

	config, err := wireguard.GeneratePeerConfig(wireguard.PeerConfig{
		PrivateKey: user.PrivateKey,
		Address:    address,
		DNS:        "1.1.1.1, 8.8.8.8",
		PublicKey:  node.PublicKey,
		Endpoint:   node.WireGuardEndpoint(),
		AllowedIPs: allowedIPs,
	})
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate config")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":     userID,
		"allowed_ips": allowedIPs,
		"config":      config,
	})
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
