// +build ignore

// Generates server TLS certificates for VPN nodes using the project CA.
// Usage: go run scripts/generate-certs.go
package main

import (
	"fmt"
	"log"
	"net"

	"github.com/m7s/vpn/internal/tlsutil"
)

func main() {
	caCertPath := "certs/ca.crt"
	caKeyPath := "certs/ca.key"

	ca, caKey, err := tlsutil.LoadOrGenerateCA(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("Failed to load/generate CA: %v", err)
	}
	fmt.Println("CA loaded from", caCertPath)

	nodes := []struct {
		name string
		ip   string
	}{
		{"vpn-us-west", "5.78.83.247"},
		{"vpn-ap-sgp", "5.223.70.143"},
	}

	for _, node := range nodes {
		certPath := fmt.Sprintf("certs/%s.crt", node.name)
		keyPath := fmt.Sprintf("certs/%s.key", node.name)

		ips := []net.IP{
			net.ParseIP(node.ip),
			net.ParseIP("127.0.0.1"),
		}

		if err := tlsutil.SaveServerCert(ca, caKey, ips, certPath, keyPath); err != nil {
			log.Fatalf("Failed to generate cert for %s: %v", node.name, err)
		}
		fmt.Printf("Generated cert for %s (%s) -> %s, %s\n", node.name, node.ip, certPath, keyPath)
	}

	fmt.Println("\nDone. Copy certs to nodes during deployment.")
}
