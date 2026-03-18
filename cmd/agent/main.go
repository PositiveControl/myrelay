package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/PositiveControl/myrelay/internal/bandwidth"
	"github.com/PositiveControl/myrelay/internal/config"
	"github.com/PositiveControl/myrelay/internal/security"
	"github.com/PositiveControl/myrelay/internal/tlsutil"
	"github.com/PositiveControl/myrelay/internal/validate"
	"github.com/PositiveControl/myrelay/internal/wireguard"
)

func main() {
	mode := flag.String("mode", envOrDefault("AGENT_MODE", "standalone"), "Agent mode: standalone or managed")
	configPath := flag.String("config", envOrDefault("CONFIG_PATH", config.DefaultPath), "Path to peer config file (standalone mode)")
	watchInterval := flag.Duration("watch", 2*time.Second, "Config file watch interval (standalone mode)")

	apiURL := flag.String("api", envOrDefault("API_URL", "http://localhost:8080"), "Control plane API base URL (managed mode)")
	iface := flag.String("interface", envOrDefault("WG_INTERFACE", "wg0"), "WireGuard interface name")
	nodeID := flag.String("node-id", envOrDefault("NODE_ID", ""), "This node's ID in the control plane (managed mode)")
	agentToken := flag.String("token", envOrDefault("AGENT_TOKEN", ""), "Agent authentication token")
	listenAddr := flag.String("listen", envOrDefault("AGENT_LISTEN", ":8081"), "Agent HTTP listen address")
	tlsCert := flag.String("tls-cert", envOrDefault("TLS_CERT_FILE", ""), "TLS certificate file")
	tlsKey := flag.String("tls-key", envOrDefault("TLS_KEY_FILE", ""), "TLS key file")
	tlsCACert := flag.String("tls-ca-cert", envOrDefault("TLS_CA_CERT", ""), "CA certificate for verifying API server (managed mode)")
	pollInterval := flag.Duration("poll", 30*time.Second, "Bandwidth poll interval")
	reportInterval := flag.Duration("report", 60*time.Second, "Report interval to control plane (managed mode)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := validate.InterfaceName(*iface); err != nil {
		log.Fatalf("invalid interface name: %v", err)
	}

	switch *mode {
	case "standalone":
		runStandalone(*iface, *configPath, *watchInterval, *pollInterval, *listenAddr, *agentToken, *tlsCert, *tlsKey)
	case "managed":
		runManaged(*iface, *apiURL, *nodeID, *agentToken, *listenAddr, *tlsCert, *tlsKey, *tlsCACert, *pollInterval, *reportInterval)
	default:
		log.Fatalf("unknown mode %q: must be 'standalone' or 'managed'", *mode)
	}
}

// runStandalone runs the agent in standalone mode: watches a local config
// file for peer changes and syncs WireGuard accordingly.
func runStandalone(iface, configPath string, watchInterval, pollInterval time.Duration, listenAddr, agentToken, tlsCert, tlsKey string) {
	log.Printf("Starting agent in standalone mode on interface %s", iface)
	log.Printf("Config file: %s", configPath)

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Auto-populate server info from WireGuard if not set.
	if cfg.Server.PublicKey == "" {
		pubKey, err := wireguard.ReadServerPublicKey(iface)
		if err != nil {
			log.Printf("Warning: could not read server public key: %v", err)
		} else {
			cfg.Server.PublicKey = pubKey
			log.Printf("Auto-detected server public key: %s...%s", pubKey[:8], pubKey[len(pubKey)-4:])
		}
	}
	if cfg.Server.Endpoint == "" || cfg.Server.Endpoint == ":51820" {
		endpoint, err := wireguard.ReadServerEndpoint(iface)
		if err != nil {
			log.Printf("Warning: could not detect server endpoint: %v", err)
		} else if endpoint != "" {
			cfg.Server.Endpoint = endpoint
			log.Printf("Auto-detected server endpoint: %s", endpoint)
		}
	}
	cfg.Server.Interface = iface
	if err := cfg.Save(); err != nil {
		log.Printf("Warning: could not save config with auto-detected values: %v", err)
	}

	// Do initial sync.
	syncPeers(iface, cfg)

	// Start bandwidth monitoring.
	mon := bandwidth.NewMonitor(iface, pollInterval)
	mon.Start()
	defer mon.Stop()

	// Start HTTP server for local status queries.
	if agentToken == "" {
		agentToken = "standalone"
	}
	srv := newStandaloneServer(listenAddr, iface, agentToken, tlsCert, mon, cfg)
	go func() {
		if tlsCert != "" && tlsKey != "" {
			log.Printf("Agent HTTPS server listening on %s", listenAddr)
			if err := srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
				log.Printf("Agent HTTPS server error: %v", err)
			}
		} else {
			log.Printf("Agent HTTP server listening on %s (no TLS)", listenAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Agent HTTP server error: %v", err)
			}
		}
	}()

	// Watch config file for changes.
	watchTicker := time.NewTicker(watchInterval)
	defer watchTicker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Agent running. Watching config every %s, polling bandwidth every %s", watchInterval, pollInterval)

	for {
		select {
		case <-watchTicker.C:
			changed, err := cfg.Reload()
			if err != nil {
				log.Printf("Failed to reload config: %v", err)
				continue
			}
			if changed {
				log.Printf("Config changed, syncing peers")
				syncPeers(iface, cfg)
			}
		case sig := <-sigCh:
			log.Printf("Received signal %s, shutting down", sig)
			return
		}
	}
}

// syncPeers makes WireGuard's peer list match the config file.
func syncPeers(iface string, cfg *config.Config) {
	// Get current WireGuard peers.
	wgPeers, err := wireguard.ShowPeers(iface)
	if err != nil {
		log.Printf("Failed to list WireGuard peers: %v", err)
		return
	}

	// Build maps.
	wgByKey := make(map[string]bool, len(wgPeers))
	for _, p := range wgPeers {
		wgByKey[p.PublicKey] = true
	}
	cfgByKey := make(map[string]config.Peer, len(cfg.Peers))
	for _, p := range cfg.ListPeers() {
		cfgByKey[p.PublicKey] = p
	}

	// Add peers that are in config but not in WireGuard.
	for key, p := range cfgByKey {
		if !wgByKey[key] {
			if err := wireguard.SyncPeers(iface, key, p.AllowedIPs, false); err != nil {
				log.Printf("Failed to add peer %s (%s): %v", p.Name, key[:16]+"...", err)
			} else {
				log.Printf("Added peer %s (%s)", p.Name, p.AllowedIPs)
			}
		}
	}

	// Remove peers that are in WireGuard but not in config.
	for key := range wgByKey {
		if _, ok := cfgByKey[key]; !ok {
			if err := wireguard.SyncPeers(iface, key, "", true); err != nil {
				log.Printf("Failed to remove peer %s: %v", key[:16]+"...", err)
			} else {
				log.Printf("Removed peer %s...", key[:16])
			}
		}
	}
}

// newStandaloneServer creates an HTTP server for standalone mode with
// status endpoints.
func newStandaloneServer(addr, iface, token, tlsCertFile string, mon *bandwidth.Monitor, cfg *config.Config) *http.Server {
	tlsEnabled := tlsCertFile != ""
	mux := http.NewServeMux()

	requireToken := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			provided := strings.TrimPrefix(h, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("GET /peers", requireToken(func(w http.ResponseWriter, r *http.Request) {
		peers := cfg.ListPeers()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(peers)
	}))
	mux.HandleFunc("GET /bandwidth", requireToken(func(w http.ResponseWriter, r *http.Request) {
		peers := mon.GetAllPeers()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(peers)
	}))
	mux.HandleFunc("GET /security", requireToken(func(w http.ResponseWriter, r *http.Request) {
		status := security.Collect(tlsEnabled, tlsCertFile)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","mode":"standalone"}`)
	})

	return &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}

// runManaged runs the agent in managed mode: an HTTP server that receives
// peer add/remove commands from a remote control plane API.
func runManaged(iface, apiURL, nodeID, agentToken, listenAddr, tlsCert, tlsKey, tlsCACert string, pollInterval, reportInterval time.Duration) {
	if nodeID == "" {
		log.Fatal("node-id is required in managed mode (set via -node-id flag or NODE_ID env var)")
	}
	if agentToken == "" {
		log.Fatal("agent token is required in managed mode (set via -token flag or AGENT_TOKEN env var)")
	}

	log.Printf("Starting agent in managed mode for node %s on interface %s", nodeID, iface)
	log.Printf("Control plane: %s", apiURL)

	// Start bandwidth monitoring.
	mon := bandwidth.NewMonitor(iface, pollInterval)
	mon.Start()
	defer mon.Stop()

	// Start the agent HTTP server for peer management.
	agentSrv := newManagedServer(listenAddr, iface, agentToken, tlsCert)
	go func() {
		if tlsCert != "" && tlsKey != "" {
			log.Printf("Agent HTTPS server listening on %s", listenAddr)
			if err := agentSrv.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
				log.Printf("Agent HTTPS server error: %v", err)
			}
		} else {
			log.Printf("WARNING: Agent HTTP server listening on %s (no TLS)", listenAddr)
			if err := agentSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Agent HTTP server error: %v", err)
			}
		}
	}()

	// Periodically report bandwidth to the control plane.
	reportTicker := time.NewTicker(reportInterval)
	defer reportTicker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Agent running. Polling every %s, reporting every %s", pollInterval, reportInterval)

	for {
		select {
		case <-reportTicker.C:
			peers := mon.GetAllPeers()
			if len(peers) == 0 {
				continue
			}
			if err := reportBandwidth(apiURL, nodeID, agentToken, tlsCACert, peers); err != nil {
				log.Printf("Failed to report bandwidth: %v", err)
			} else {
				log.Printf("Reported bandwidth for %d peers", len(peers))
			}
		case sig := <-sigCh:
			log.Printf("Received signal %s, shutting down", sig)
			return
		}
	}
}

// newManagedServer creates the HTTP server for managed mode (peer add/remove from control plane).
func newManagedServer(addr, iface, token, tlsCertFile string) *http.Server {
	tlsEnabled := tlsCertFile != ""
	mux := http.NewServeMux()

	requireToken := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			provided := strings.TrimPrefix(h, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("POST /peers", requireToken(handleAddPeer(iface)))
	mux.HandleFunc("POST /peers/remove", requireToken(handleRemovePeer(iface)))
	mux.HandleFunc("GET /peers", requireToken(handleListPeers(iface)))
	mux.HandleFunc("GET /security", requireToken(func(w http.ResponseWriter, r *http.Request) {
		status := security.Collect(tlsEnabled, tlsCertFile)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","mode":"managed"}`)
	})

	return &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}

type addPeerRequest struct {
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
}

func handleAddPeer(iface string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req addPeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}
		if req.PublicKey == "" || req.AllowedIPs == "" {
			http.Error(w, `{"error":"public_key and allowed_ips required"}`, http.StatusBadRequest)
			return
		}
		if err := validate.WireGuardKey(req.PublicKey); err != nil {
			http.Error(w, `{"error":"invalid public_key"}`, http.StatusBadRequest)
			return
		}
		if err := validate.CIDR(req.AllowedIPs); err != nil {
			http.Error(w, `{"error":"invalid allowed_ips"}`, http.StatusBadRequest)
			return
		}

		if err := wireguard.SyncPeers(iface, req.PublicKey, req.AllowedIPs, false); err != nil {
			log.Printf("Failed to add peer %s: %v", req.PublicKey, err)
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		log.Printf("Added peer %s with allowed IPs %s", req.PublicKey, req.AllowedIPs)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"added","public_key":"%s"}`, req.PublicKey)
	}
}

type removePeerRequest struct {
	PublicKey string `json:"public_key"`
}

func handleRemovePeer(iface string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req removePeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PublicKey == "" {
			http.Error(w, `{"error":"public_key required"}`, http.StatusBadRequest)
			return
		}
		if err := validate.WireGuardKey(req.PublicKey); err != nil {
			http.Error(w, `{"error":"invalid public_key"}`, http.StatusBadRequest)
			return
		}

		if err := wireguard.SyncPeers(iface, req.PublicKey, "", true); err != nil {
			log.Printf("Failed to remove peer %s: %v", req.PublicKey, err)
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		log.Printf("Removed peer %s", req.PublicKey)
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleListPeers(iface string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := wireguard.ShowPeers(iface)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	}
}

func reportBandwidth(apiURL, nodeID, token, caCertPath string, peers []bandwidth.PeerBandwidth) error {
	payload := map[string]any{
		"node_id": nodeID,
		"peers":   peers,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := apiURL + "/api/nodes/" + nodeID + "/bandwidth"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	if caCertPath != "" {
		tlsCfg, err := tlsutil.ClientTLSConfig(caCertPath)
		if err != nil {
			return fmt.Errorf("failed to load CA cert: %w", err)
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Control plane returned status %d", resp.StatusCode)
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
