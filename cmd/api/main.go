package main

import (
	"flag"
	"log"
	"os"

	"github.com/m7s/vpn/internal/api"
	"github.com/m7s/vpn/internal/db"
)

func main() {
	addr := flag.String("addr", envOrDefault("LISTEN_ADDR", ":8080"), "HTTP listen address")
	adminToken := flag.String("admin-token", envOrDefault("ADMIN_TOKEN", ""), "Admin API token")
	dbPath := flag.String("db", envOrDefault("DB_PATH", "vpn.db"), "SQLite database path")
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

	database, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	log.Printf("Starting VPN control plane API (db: %s)", *dbPath)

	auth := api.NewAuth(*adminToken, database)
	srv := api.NewServer(*addr, database, auth)

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
