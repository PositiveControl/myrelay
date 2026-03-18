package api

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/PositiveControl/myrelay/internal/agent"
	"github.com/PositiveControl/myrelay/internal/api/handlers"
	"github.com/PositiveControl/myrelay/internal/db"
	"github.com/PositiveControl/myrelay/internal/httputil"
)

// Server is the control plane HTTP API server.
type Server struct {
	addr      string
	db        *db.DB
	auth      *Auth
	agents    *agent.Client
	mux       *http.ServeMux
	server    *http.Server
	tlsConfig *tls.Config
	useTLS    bool
}

// NewServer creates a configured API server.
func NewServer(addr string, database *db.DB, auth *Auth) *Server {
	s := &Server{
		addr:   addr,
		db:     database,
		auth:   auth,
		agents: agent.NewClient(),
		mux:    http.NewServeMux(),
	}

	// Restore agent registrations from the database.
	if err := s.restoreAgents(); err != nil {
		log.Printf("Warning: failed to restore agent registrations: %v", err)
	}

	s.registerRoutes()
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.logging(s.mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

// SetTLSConfig configures TLS for the server.
func (s *Server) SetTLSConfig(tlsConfig *tls.Config) {
	s.tlsConfig = tlsConfig
	s.server.TLSConfig = tlsConfig
	s.useTLS = true
}

// SetAgentTLS configures the agent client to use TLS with the given CA config.
func (s *Server) SetAgentTLS(tlsConfig *tls.Config) {
	s.agents.SetTLSConfig(tlsConfig)
}

// restoreAgents re-registers agent URLs from persisted node data.
func (s *Server) restoreAgents() error {
	nodes, err := s.db.ListNodes()
	if err != nil {
		return err
	}
	tokens, err := s.db.ListNodeTokens()
	if err != nil {
		return err
	}
	for _, node := range nodes {
		scheme := "http"
		if s.useTLS {
			scheme = "https"
		}
		agentURL := fmt.Sprintf("%s://%s:8081", scheme, node.IP)
		token := tokens[node.ID]
		s.agents.RegisterNode(node.ID, agentURL, token)
		log.Printf("Restored agent registration for node %s (%s)", node.ID, node.IP)
	}
	return nil
}

// Start begins listening for requests. Uses TLS if configured. Blocks until the server stops.
func (s *Server) Start() error {
	// Re-register agents with correct scheme now that TLS state is finalized.
	if err := s.restoreAgents(); err != nil {
		log.Printf("Warning: failed to restore agent registrations: %v", err)
	}

	if s.useTLS {
		log.Printf("API server listening on %s (TLS)", s.addr)
		return s.server.ListenAndServeTLS("", "") // certs provided via TLSConfig
	}
	log.Printf("WARNING: API server listening on %s (no TLS)", s.addr)
	return s.server.ListenAndServe()
}

// registerRoutes wires up all API endpoints.
func (s *Server) registerRoutes() {
	userHandler := handlers.NewUserHandler(s.db, s.agents)
	nodeHandler := handlers.NewNodeHandler(s.db, s.auth, s.agents)

	// Public.
	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	// Admin-only.
	s.mux.HandleFunc("POST /api/users", s.auth.RequireAdmin(userHandler.Create))
	s.mux.HandleFunc("GET /api/users", s.auth.RequireAdmin(userHandler.List))
	s.mux.HandleFunc("GET /api/users/{id}", s.auth.RequireAdmin(userHandler.Get))
	s.mux.HandleFunc("DELETE /api/users/{id}", s.auth.RequireAdmin(userHandler.Delete))
	s.mux.HandleFunc("GET /api/users/{id}/rules", s.auth.RequireAdmin(userHandler.ListRules))
	s.mux.HandleFunc("POST /api/users/{id}/rules", s.auth.RequireAdmin(userHandler.AddRule))
	s.mux.HandleFunc("DELETE /api/users/{id}/rules/{ruleId}", s.auth.RequireAdmin(userHandler.RemoveRule))
	s.mux.HandleFunc("GET /api/users/{id}/config", s.auth.RequireAdmin(userHandler.Config))
	s.mux.HandleFunc("POST /api/users/{id}/regen-config", s.auth.RequireAdmin(s.handleRegenConfig))

	s.mux.HandleFunc("POST /api/nodes", s.auth.RequireAdmin(nodeHandler.Register))
	s.mux.HandleFunc("GET /api/nodes", s.auth.RequireAdmin(nodeHandler.List))
	s.mux.HandleFunc("GET /api/nodes/{id}", s.auth.RequireAdmin(nodeHandler.Get))
	s.mux.HandleFunc("POST /api/nodes/{id}/sync", s.auth.RequireAdmin(nodeHandler.Sync))
	s.mux.HandleFunc("GET /api/nodes/{id}/bandwidth", s.auth.RequireAdmin(nodeHandler.GetBandwidth))
	s.mux.HandleFunc("GET /api/nodes/{id}/security", s.auth.RequireAdmin(nodeHandler.GetSecurity))

	// Node or admin.
	s.mux.HandleFunc("POST /api/nodes/{id}/bandwidth", s.auth.RequireNodeOrAdmin(nodeHandler.ReportBandwidth))

	// Public onboarding pages (no auth required).
	s.mux.HandleFunc("GET /onboard/{token}", s.handleOnboardPage)
	s.mux.HandleFunc("GET /onboard/{token}/config", s.handleOnboardConfig)
	s.mux.HandleFunc("GET /onboard/{token}/qr", s.handleOnboardQR)
}

// handleRegenConfig regenerates a user's onboarding token and config.
func (s *Server) handleRegenConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	user, err := s.db.GetUser(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	clientConfig, err := s.buildClientConfig(user)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate config")
		return
	}

	// Generate new onboarding token.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	token := hex.EncodeToString(b)
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)
	if err := s.db.CreateOnboardingToken(user.ID, token, expiresAt); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to save token")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"client_config":  clientConfig,
		"onboarding_url": "/onboard/" + token,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// logging is a middleware that logs each request.
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, wrapped.status, time.Since(start))
	})
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
