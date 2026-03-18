// +build ignore

// Generates server TLS certificates for VPN nodes using the project CA.
// Usage: go run scripts/generate-certs.go -nodes "node1=1.2.3.4,node2=5.6.7.8"
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/PositiveControl/myrelay/internal/tlsutil"
)

func main() {
	nodesFlag := flag.String("nodes", "", "Comma-separated node=ip pairs (e.g., node1=1.2.3.4,node2=5.6.7.8)")
	flag.Parse()

	if *nodesFlag == "" {
		log.Fatal("Usage: go run scripts/generate-certs.go -nodes \"node1=1.2.3.4,node2=5.6.7.8\"")
	}

	caCertPath := "certs/ca.crt"
	caKeyPath := "certs/ca.key"

	ca, caKey, err := tlsutil.LoadOrGenerateCA(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("Failed to load/generate CA: %v", err)
	}
	fmt.Println("CA loaded from", caCertPath)

	for _, entry := range strings.Split(*nodesFlag, ",") {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid node entry %q: expected name=ip", entry)
		}
		name, ip := parts[0], parts[1]

		certPath := fmt.Sprintf("certs/%s.crt", name)
		keyPath := fmt.Sprintf("certs/%s.key", name)

		ips := []net.IP{
			net.ParseIP(ip),
			net.ParseIP("127.0.0.1"),
		}

		if err := tlsutil.SaveServerCert(ca, caKey, ips, certPath, keyPath); err != nil {
			log.Fatalf("Failed to generate cert for %s: %v", name, err)
		}
		fmt.Printf("Generated cert for %s (%s) -> %s, %s\n", name, ip, certPath, keyPath)
	}

	fmt.Println("\nDone. Copy certs to nodes during deployment.")
}
