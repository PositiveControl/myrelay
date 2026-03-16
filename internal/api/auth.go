package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"

	"github.com/m7s/vpn/internal/httputil"
)

// Auth handles API authentication with admin and per-node tokens.
type Auth struct {
	adminToken string

	mu         sync.RWMutex
	nodeTokens map[string]string // node ID -> token
}

// NewAuth creates an Auth with the given admin token.
func NewAuth(adminToken string) *Auth {
	return &Auth{
		adminToken: adminToken,
		nodeTokens: make(map[string]string),
	}
}

// GenerateNodeToken creates and stores a token for a node. Returns the token.
func (a *Auth) GenerateNodeToken(nodeID string) (string, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	a.nodeTokens[nodeID] = token
	a.mu.Unlock()
	return token, nil
}

// RevokeNodeToken removes a node's token.
func (a *Auth) RevokeNodeToken(nodeID string) {
	a.mu.Lock()
	delete(a.nodeTokens, nodeID)
	a.mu.Unlock()
}

// RequireAdmin returns middleware that requires a valid admin token.
func (a *Auth) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r)
		if !secureCompare(token, a.adminToken) {
			httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// RequireNodeOrAdmin returns middleware that accepts either a valid node token
// (matched to the {id} path parameter) or the admin token.
func (a *Auth) RequireNodeOrAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r)

		// Check admin token first.
		if secureCompare(token, a.adminToken) {
			next(w, r)
			return
		}

		// Check node token.
		nodeID := r.PathValue("id")
		a.mu.RLock()
		expected, ok := a.nodeTokens[nodeID]
		a.mu.RUnlock()

		if ok && secureCompare(token, expected) {
			next(w, r)
			return
		}

		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
	}
}

// GenerateToken creates a random 32-byte hex token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return h[7:]
	}
	return ""
}

func secureCompare(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
