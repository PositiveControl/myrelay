package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/m7s/vpn/internal/bandwidth"
)

func main() {
	apiURL := flag.String("api", envOrDefault("API_URL", "http://localhost:8080"), "Control plane API base URL")
	iface := flag.String("interface", envOrDefault("WG_INTERFACE", "wg0"), "WireGuard interface name")
	nodeID := flag.String("node-id", envOrDefault("NODE_ID", ""), "This node's ID in the control plane")
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
			if err := reportBandwidth(*apiURL, *nodeID, peers); err != nil {
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

func reportBandwidth(apiURL, nodeID string, peers []bandwidth.PeerBandwidth) error {
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
