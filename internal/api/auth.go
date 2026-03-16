package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/m7s/vpn/internal/db"
	"github.com/m7s/vpn/internal/httputil"
)

// Auth handles API authentication with admin and per-node tokens.
type Auth struct {
	adminToken string
	db         *db.DB
}

// NewAuth creates an Auth with the given admin token and database.
func NewAuth(adminToken string, database *db.DB) *Auth {
	return &Auth{
		adminToken: adminToken,
		db:         database,
	}
}

// GenerateNodeToken creates and stores a token for a node. Returns the token.
func (a *Auth) GenerateNodeToken(nodeID string) (string, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", err
	}
	// Token is saved to DB by the node handler after node creation.
	return token, nil
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

		// Check node token from database.
		nodeID := r.PathValue("id")
		expected, err := a.db.GetNodeToken(nodeID)
		if err == nil && expected != "" && secureCompare(token, expected) {
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
