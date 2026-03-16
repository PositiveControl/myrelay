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

	"github.com/m7s/vpn/internal/bandwidth"
	"github.com/m7s/vpn/internal/wireguard"
)

func main() {
	apiURL := flag.String("api", envOrDefault("API_URL", "http://localhost:8080"), "Control plane API base URL")
	iface := flag.String("interface", envOrDefault("WG_INTERFACE", "wg0"), "WireGuard interface name")
	nodeID := flag.String("node-id", envOrDefault("NODE_ID", ""), "This node's ID in the control plane")
	agentToken := flag.String("token", envOrDefault("AGENT_TOKEN", ""), "Agent authentication token")
	listenAddr := flag.String("listen", envOrDefault("AGENT_LISTEN", ":8081"), "Agent HTTP listen address")
	pollInterval := flag.Duration("poll", 30*time.Second, "Bandwidth poll interval")
	reportInterval := flag.Duration("report", 60*time.Second, "Report interval to control plane")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if *nodeID == "" {
		log.Fatal("node-id is required (set via -node-id flag or NODE_ID env var)")
	}

	log.Printf("Starting VPN agent for node %s on interface %s", *nodeID, *iface)
	log.Printf("Control plane: %s", *apiURL)

	// Start bandwidth monitoring.
	mon := bandwidth.NewMonitor(*iface, *pollInterval)
	mon.Start()
	defer mon.Stop()

	// Start the agent HTTP server for peer management.
	agentSrv := newAgentServer(*listenAddr, *iface, *agentToken)
	go func() {
		log.Printf("Agent HTTP server listening on %s", *listenAddr)
		if err := agentSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Agent HTTP server error: %v", err)
		}
	}()

	// Periodically report bandwidth to the control plane.
	reportTicker := time.NewTicker(*reportInterval)
	defer reportTicker.Stop()

	// Handle shutdown signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Agent running. Polling every %s, reporting every %s", *pollInterval, *reportInterval)

	for {
		select {
		case <-reportTicker.C:
			peers := mon.GetAllPeers()
			if len(peers) == 0 {
				continue
			}
			if err := reportBandwidth(*apiURL, *nodeID, *agentToken, peers); err != nil {
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

// agentServer handles peer add/remove requests from the control plane.
func newAgentServer(addr, iface, token string) *http.Server {
	mux := http.NewServeMux()

	requireToken := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if token == "" {
				next(w, r)
				return
			}
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
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
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
		pubkey := req.PublicKey

		if err := wireguard.SyncPeers(iface, pubkey, "", true); err != nil {
			log.Printf("Failed to remove peer %s: %v", pubkey, err)
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		log.Printf("Removed peer %s", pubkey)
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

func reportBandwidth(apiURL, nodeID, token string, peers []bandwidth.PeerBandwidth) error {
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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
