package wireguard

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"
)

// KeyPair holds a WireGuard private and public key.
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// PeerTransfer holds per-peer bandwidth transfer data parsed from wg show.
type PeerTransfer struct {
	PublicKey      string
	BytesReceived int64
	BytesSent     int64
}

// PeerConfig holds values needed to render a WireGuard peer configuration block.
type PeerConfig struct {
	PrivateKey string
	Address    string
	DNS        string
	PublicKey  string // Server public key
	Endpoint   string
	AllowedIPs string
}

// GenerateKeyPair generates a new WireGuard private/public key pair using the
// wg command-line tool. Requires wireguard-tools to be installed.
func GenerateKeyPair() (*KeyPair, error) {
	privCmd := exec.Command("wg", "genkey")
	privOut, err := privCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wg genkey: %w", err)
	}
	privateKey := strings.TrimSpace(string(privOut))

	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(privateKey)
	pubOut, err := pubCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wg pubkey: %w", err)
	}
	publicKey := strings.TrimSpace(string(pubOut))

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// GeneratePeerConfig renders a complete WireGuard client configuration file
// from the given PeerConfig values.
func GeneratePeerConfig(cfg PeerConfig) (string, error) {
	const tmpl = `[Interface]
PrivateKey = {{ .PrivateKey }}
Address = {{ .Address }}
DNS = {{ .DNS }}

[Peer]
PublicKey = {{ .PublicKey }}
Endpoint = {{ .Endpoint }}
AllowedIPs = {{ .AllowedIPs }}
PersistentKeepalive = 25
`
	t, err := template.New("peer").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, cfg); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// ParseWgShow parses the output of `wg show <interface> transfer` and returns
// per-peer transfer statistics. Each output line has the format:
//
//	<public_key>\t<bytes_received>\t<bytes_sent>
func ParseWgShow(output string) ([]PeerTransfer, error) {
	var peers []PeerTransfer
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("unexpected line format (got %d fields): %q", len(fields), line)
		}

		received, err := strconv.ParseInt(strings.TrimSpace(fields[1]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse bytes received for peer %s: %w", fields[0], err)
		}

		sent, err := strconv.ParseInt(strings.TrimSpace(fields[2]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse bytes sent for peer %s: %w", fields[0], err)
		}

		peers = append(peers, PeerTransfer{
			PublicKey:      strings.TrimSpace(fields[0]),
			BytesReceived: received,
			BytesSent:     sent,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan output: %w", err)
	}

	return peers, nil
}

// CreateInterface creates a WireGuard interface, generates a keypair,
// assigns an address, and brings it up. Returns the public key.
func CreateInterface(name string, listenPort int, address string) (string, error) {
	// Create the interface.
	if out, err := exec.Command("ip", "link", "add", name, "type", "wireguard").CombinedOutput(); err != nil {
		return "", fmt.Errorf("ip link add %s: %s: %w", name, string(out), err)
	}

	// Generate keypair.
	kp, err := GenerateKeyPair()
	if err != nil {
		// Clean up the interface we just created.
		_ = exec.Command("ip", "link", "delete", name).Run()
		return "", fmt.Errorf("generate keypair: %w", err)
	}

	// Write private key to a temp file with restricted permissions.
	tmpFile := fmt.Sprintf("/tmp/wg-privkey-%s", name)
	if err := os.WriteFile(tmpFile, []byte(kp.PrivateKey), 0600); err != nil {
		_ = exec.Command("ip", "link", "delete", name).Run()
		return "", fmt.Errorf("write private key: %w", err)
	}
	defer os.Remove(tmpFile)

	// Configure WireGuard with private key and listen port.
	if out, err := exec.Command("wg", "set", name, "private-key", tmpFile, "listen-port", strconv.Itoa(listenPort)).CombinedOutput(); err != nil {
		_ = exec.Command("ip", "link", "delete", name).Run()
		return "", fmt.Errorf("wg set %s: %s: %w", name, string(out), err)
	}

	// Assign address.
	if out, err := exec.Command("ip", "addr", "add", address, "dev", name).CombinedOutput(); err != nil {
		_ = exec.Command("ip", "link", "delete", name).Run()
		return "", fmt.Errorf("ip addr add %s: %s: %w", address, string(out), err)
	}

	// Bring interface up.
	if out, err := exec.Command("ip", "link", "set", name, "up").CombinedOutput(); err != nil {
		_ = exec.Command("ip", "link", "delete", name).Run()
		return "", fmt.Errorf("ip link set %s up: %s: %w", name, string(out), err)
	}

	// Extract subnet from address for NAT rule.
	_, subnet, err := net.ParseCIDR(address)
	if err == nil {
		_ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet.String(), "-o", "eth0", "-j", "MASQUERADE").Run()
	}

	return kp.PublicKey, nil
}

// DestroyInterface tears down a WireGuard interface and cleans up NAT rules.
func DestroyInterface(name string, subnet string) error {
	// Remove NAT rule (best-effort).
	_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", "eth0", "-j", "MASQUERADE").Run()

	// Delete the interface.
	if out, err := exec.Command("ip", "link", "delete", name).CombinedOutput(); err != nil {
		return fmt.Errorf("ip link delete %s: %s: %w", name, string(out), err)
	}
	return nil
}

// ListInterfaces returns active WireGuard interface names.
func ListInterfaces() ([]string, error) {
	cmd := exec.Command("wg", "show", "interfaces")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wg show interfaces: %w", err)
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}
	return strings.Fields(raw), nil
}

// PeerInfo holds summary info about a configured peer.
type PeerInfo struct {
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
	Endpoint   string `json:"endpoint,omitempty"`
	LastHandshake string `json:"last_handshake,omitempty"`
}

// ShowPeers returns info about all configured peers on an interface by parsing `wg show`.
func ShowPeers(interfaceName string) ([]PeerInfo, error) {
	cmd := exec.Command("wg", "show", interfaceName, "dump")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wg show %s dump: %w", interfaceName, err)
	}

	var peers []PeerInfo
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	first := true
	for scanner.Scan() {
		if first {
			first = false // skip the interface line
			continue
		}
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 4 {
			continue
		}
		p := PeerInfo{
			PublicKey:  fields[0],
			AllowedIPs: fields[3],
		}
		if fields[2] != "(none)" {
			p.Endpoint = fields[2]
		}
		if len(fields) > 4 && fields[4] != "0" {
			p.LastHandshake = fields[4]
		}
		peers = append(peers, p)
	}
	if peers == nil {
		peers = []PeerInfo{}
	}
	return peers, scanner.Err()
}

// ApplyConfig writes a WireGuard configuration and brings the interface up
// using wg-quick.
func ApplyConfig(interfaceName, configPath string) error {
	// Bring down existing interface (ignore error if not up)
	downCmd := exec.Command("wg-quick", "down", interfaceName)
	_ = downCmd.Run()

	upCmd := exec.Command("wg-quick", "up", configPath)
	if out, err := upCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick up %s: %s: %w", configPath, string(out), err)
	}
	return nil
}

// ReadServerPublicKey reads the server's own public key from a WireGuard
// interface by parsing the first line of `wg show <iface> dump`.
func ReadServerPublicKey(interfaceName string) (string, error) {
	cmd := exec.Command("wg", "show", interfaceName, "public-key")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg show %s public-key: %w", interfaceName, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ReadServerEndpoint attempts to determine the server's public endpoint
// by reading the interface's listen port and discovering the public IP.
// Returns "IP:port" or an error.
func ReadServerEndpoint(interfaceName string) (string, error) {
	cmd := exec.Command("wg", "show", interfaceName, "listen-port")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg show %s listen-port: %w", interfaceName, err)
	}
	port := strings.TrimSpace(string(out))
	if port == "" {
		port = "51820"
	}

	// Try to determine external IP from default route interface.
	ipCmd := exec.Command("hostname", "-I")
	ipOut, err := ipCmd.Output()
	if err != nil {
		return ":" + port, nil
	}
	fields := strings.Fields(string(ipOut))
	if len(fields) > 0 {
		return fields[0] + ":" + port, nil
	}
	return ":" + port, nil
}

// SyncPeers calls `wg set` to add or remove a peer on a live interface without
// restarting.
func SyncPeers(interfaceName string, publicKey string, allowedIPs string, remove bool) error {
	if remove {
		cmd := exec.Command("wg", "set", interfaceName, "peer", publicKey, "remove")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("wg set remove peer: %s: %w", string(out), err)
		}
		return nil
	}

	cmd := exec.Command("wg", "set", interfaceName, "peer", publicKey, "allowed-ips", allowedIPs)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg set add peer: %s: %w", string(out), err)
	}
	return nil
}
