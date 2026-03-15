package main

import (
	"flag"
	"log"
	"os"

	"github.com/m7s/vpn/internal/api"
)

func main() {
	addr := flag.String("addr", envOrDefault("LISTEN_ADDR", ":8080"), "HTTP listen address")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting VPN control plane API")

	store := api.NewStore()
	srv := api.NewServer(*addr, store)

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
