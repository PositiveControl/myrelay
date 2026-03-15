package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/m7s/vpn/internal/httputil"
	"github.com/m7s/vpn/internal/models"
	"github.com/m7s/vpn/internal/wireguard"
)

// UserHandler handles HTTP requests for user management.
type UserHandler struct {
	mu    sync.RWMutex
	users map[string]*models.User
}

// NewUserHandler creates a handler backed by the given user map.
func NewUserHandler(users map[string]*models.User) *UserHandler {
	return &UserHandler{users: users}
}

// createUserRequest is the JSON body for creating a new user.
type createUserRequest struct {
	Email string      `json:"email"`
	Plan  models.Plan `json:"plan"`
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

	h.mu.Lock()
	h.users[user.ID] = user
	h.mu.Unlock()

	httputil.WriteJSON(w, http.StatusCreated, user)
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
	_, ok := h.users[id]
	if !ok {
		h.mu.Unlock()
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	delete(h.users, id)
	h.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
