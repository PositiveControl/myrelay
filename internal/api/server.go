package api

import (
	"log"
	"net/http"
	"time"

	"github.com/m7s/vpn/internal/api/handlers"
	"github.com/m7s/vpn/internal/httputil"
	"github.com/m7s/vpn/internal/models"
)

// Store is a simple in-memory data store. Replace with a real database later.
type Store struct {
	Users map[string]*models.User
	Nodes map[string]*models.Node
}

// NewStore creates an empty in-memory store.
func NewStore() *Store {
	return &Store{
		Users: make(map[string]*models.User),
		Nodes: make(map[string]*models.Node),
	}
}

// Server is the control plane HTTP API server.
type Server struct {
	addr   string
	store  *Store
	mux    *http.ServeMux
	server *http.Server
}

// NewServer creates a configured API server.
func NewServer(addr string, store *Store) *Server {
	s := &Server{
		addr:  addr,
		store: store,
		mux:   http.NewServeMux(),
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

// Start begins listening for HTTP requests. Blocks until the server stops.
func (s *Server) Start() error {
	log.Printf("API server listening on %s", s.addr)
	return s.server.ListenAndServe()
}

// registerRoutes wires up all API endpoints.
func (s *Server) registerRoutes() {
	userHandler := handlers.NewUserHandler(s.store.Users)
	nodeHandler := handlers.NewNodeHandler(s.store.Nodes)

	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	s.mux.HandleFunc("POST /api/users", userHandler.Create)
	s.mux.HandleFunc("GET /api/users", userHandler.List)
	s.mux.HandleFunc("GET /api/users/{id}", userHandler.Get)
	s.mux.HandleFunc("DELETE /api/users/{id}", userHandler.Delete)

	s.mux.HandleFunc("GET /api/nodes", nodeHandler.List)
	s.mux.HandleFunc("GET /api/nodes/{id}", nodeHandler.Get)
	s.mux.HandleFunc("POST /api/nodes/{id}/sync", nodeHandler.Sync)
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
