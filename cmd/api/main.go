package main

import (
	"flag"
	"log"
	"os"

	"github.com/m7s/vpn/internal/api"
)

func main() {
	addr := flag.String("addr", envOrDefault("LISTEN_ADDR", ":8080"), "HTTP listen address")
	adminToken := flag.String("admin-token", envOrDefault("ADMIN_TOKEN", ""), "Admin API token")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if *adminToken == "" {
		generated, err := api.GenerateToken()
		if err != nil {
			log.Fatalf("failed to generate admin token: %v", err)
		}
		*adminToken = generated
		log.Printf("No ADMIN_TOKEN set — generated one: %s", *adminToken)
	}

	log.Printf("Starting VPN control plane API")

	auth := api.NewAuth(*adminToken)
	store := api.NewStore()
	srv := api.NewServer(*addr, store, auth)

	if err := srv.Start(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
