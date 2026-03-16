package api

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/m7s/vpn/internal/agent"
	"github.com/m7s/vpn/internal/api/handlers"
	"github.com/m7s/vpn/internal/db"
	"github.com/m7s/vpn/internal/httputil"
)

// Server is the control plane HTTP API server.
type Server struct {
	addr   string
	db     *db.DB
	auth   *Auth
	agents *agent.Client
	mux    *http.ServeMux
	server *http.Server
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
		agentURL := fmt.Sprintf("http://%s:8081", node.IP)
		token := tokens[node.ID]
		s.agents.RegisterNode(node.ID, agentURL, token)
		log.Printf("Restored agent registration for node %s (%s)", node.ID, node.IP)
	}
	return nil
}

// Start begins listening for HTTP requests. Blocks until the server stops.
func (s *Server) Start() error {
	log.Printf("API server listening on %s", s.addr)
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

	s.mux.HandleFunc("POST /api/nodes", s.auth.RequireAdmin(nodeHandler.Register))
	s.mux.HandleFunc("GET /api/nodes", s.auth.RequireAdmin(nodeHandler.List))
	s.mux.HandleFunc("GET /api/nodes/{id}", s.auth.RequireAdmin(nodeHandler.Get))
	s.mux.HandleFunc("POST /api/nodes/{id}/sync", s.auth.RequireAdmin(nodeHandler.Sync))
	s.mux.HandleFunc("GET /api/nodes/{id}/bandwidth", s.auth.RequireAdmin(nodeHandler.GetBandwidth))

	// Node or admin.
	s.mux.HandleFunc("POST /api/nodes/{id}/bandwidth", s.auth.RequireNodeOrAdmin(nodeHandler.ReportBandwidth))
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
