package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"os"

	"github.com/PositiveControl/myrelay/internal/api"
	"github.com/PositiveControl/myrelay/internal/db"
	"github.com/PositiveControl/myrelay/internal/tlsutil"
)

func main() {
	addr := flag.String("addr", envOrDefault("LISTEN_ADDR", ":8080"), "HTTP listen address")
	adminToken := flag.String("admin-token", envOrDefault("ADMIN_TOKEN", ""), "Admin API token")
	dbPath := flag.String("db", envOrDefault("DB_PATH", "vpn.db"), "SQLite database path")
	tlsCert := flag.String("tls-cert", envOrDefault("TLS_CERT_FILE", ""), "TLS certificate file")
	tlsKey := flag.String("tls-key", envOrDefault("TLS_KEY_FILE", ""), "TLS key file")
	tlsCACert := flag.String("tls-ca-cert", envOrDefault("TLS_CA_CERT", ""), "CA cert file (auto-generates server cert if --tls-cert is empty)")
	tlsCAKey := flag.String("tls-ca-key", envOrDefault("TLS_CA_KEY", ""), "CA key file (used with --tls-ca-cert)")
	serverIP := flag.String("server-ip", envOrDefault("SERVER_IP", ""), "Server IP for auto-generated TLS cert")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if *adminToken == "" {
		generated, err := api.GenerateToken()
		if err != nil {
			log.Fatalf("failed to generate admin token: %v", err)
		}
		*adminToken = generated
		log.Printf("No ADMIN_TOKEN set — generated one (see stderr)")
		os.Stderr.WriteString("Generated admin token: " + *adminToken + "\n")
	}

	database, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	log.Printf("Starting VPN control plane API (db: %s)", *dbPath)

	auth := api.NewAuth(*adminToken, database)
	srv := api.NewServer(*addr, database, auth)

	// Configure TLS if cert/key provided directly
	if *tlsCert != "" && *tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("failed to load TLS certificate: %v", err)
		}
		srv.SetTLSConfig(tlsutil.ServerTLSConfig(cert))
		// Configure agent client TLS if CA cert available
		if *tlsCACert != "" {
			agentTLS, err := tlsutil.ClientTLSConfig(*tlsCACert)
			if err != nil {
				log.Fatalf("failed to load CA cert for agent client: %v", err)
			}
			srv.SetAgentTLS(agentTLS)
		}
		log.Printf("TLS enabled with certificate from %s", *tlsCert)
	} else if *tlsCACert != "" && *tlsCAKey != "" && *serverIP != "" {
		// Auto-generate server cert from CA
		ca, caKey, err := tlsutil.LoadOrGenerateCA(*tlsCACert, *tlsCAKey)
		if err != nil {
			log.Fatalf("failed to load CA: %v", err)
		}
		ip := net.ParseIP(*serverIP)
		if ip == nil {
			log.Fatalf("invalid server IP: %s", *serverIP)
		}
		cert, err := tlsutil.GenerateServerCert(ca, caKey, []net.IP{ip, net.ParseIP("127.0.0.1")})
		if err != nil {
			log.Fatalf("failed to generate server cert: %v", err)
		}
		srv.SetTLSConfig(tlsutil.ServerTLSConfig(cert))
		// Configure agent client TLS with the CA cert
		agentTLS, err := tlsutil.ClientTLSConfig(*tlsCACert)
		if err != nil {
			log.Fatalf("failed to load CA cert for agent client: %v", err)
		}
		srv.SetAgentTLS(agentTLS)
		log.Printf("TLS enabled with auto-generated cert for IP %s", *serverIP)
	}

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
