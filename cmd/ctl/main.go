package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/PositiveControl/myrelay/internal/config"
	"github.com/PositiveControl/myrelay/pkg/tlsutil"
	"github.com/PositiveControl/myrelay/pkg/wireguard"
)

var (
	apiURL     string
	token      string
	client     = &http.Client{Timeout: 10 * time.Second}
	configPath string
)

func main() {
	apiURL = envOrDefault("VPN_API_URL", "")
	token = envOrDefault("VPN_ADMIN_TOKEN", "")
	configPath = envOrDefault("VPN_CONFIG", config.DefaultPath)

	// Configure TLS for HTTPS API URLs.
	if caPath := os.Getenv("TLS_CA_CERT"); caPath != "" {
		tlsCfg, err := tlsutil.ClientTLSConfig(caPath)
		if err != nil {
			fatal("Failed to load CA cert %s: %v", caPath, err)
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	} else if strings.HasPrefix(apiURL, "https://") {
		fmt.Fprintln(os.Stderr, "Warning: using HTTPS without TLS_CA_CERT — certificate verification disabled")
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else if strings.HasPrefix(apiURL, "http://") && !isLocalhost(apiURL) {
		fmt.Fprintln(os.Stderr, "Warning: using plaintext HTTP to a remote host — tokens are sent in the clear")
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	// === Local (standalone) commands ===
	case "peer":
		if len(args) == 0 {
			cmdPeerList()
			return
		}
		switch args[0] {
		case "add":
			requireArg(args, 1, "peer name")
			cmdPeerAdd(args[1])
		case "remove", "rm":
			requireArg(args, 1, "peer name")
			cmdPeerRemove(args[1])
		case "list", "ls":
			cmdPeerList()
		default:
			fmt.Fprintf(os.Stderr, "Unknown peer subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "config":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: vpnctl config show <peer-name>")
			os.Exit(1)
		}
		switch args[0] {
		case "show":
			requireArg(args, 1, "peer name")
			cmdConfigShow(args[1])
		default:
			// Treat as peer name: vpnctl config <name>
			cmdConfigShow(args[0])
		}
	case "qr":
		requireArg(args, 0, "peer name")
		cmdQR(args[0])

	// === Remote (managed/API) commands ===
	case "status":
		requireAPI()
		cmdStatus()
	case "nodes":
		requireAPI()
		if len(args) == 0 {
			cmdNodesList()
			return
		}
		switch args[0] {
		case "list", "ls":
			cmdNodesList()
		case "get":
			requireArg(args, 1, "node ID")
			cmdNodesGet(args[1])
		case "add":
			cmdNodesAdd(args[1:])
		case "bandwidth", "bw":
			requireArg(args, 1, "node ID")
			cmdNodesBandwidth(args[1])
		default:
			cmdNodesGet(args[0])
		}
	case "users":
		requireAPI()
		if len(args) == 0 {
			cmdUsersList()
			return
		}
		switch args[0] {
		case "list", "ls":
			cmdUsersList()
		case "get":
			requireArg(args, 1, "user ID or email")
			cmdUsersGet(args[1])
		case "add", "create":
			cmdUsersCreate(args[1:])
		case "delete", "rm":
			requireArg(args, 1, "user ID")
			cmdUsersDelete(args[1])
		case "rules":
			requireArg(args, 1, "user ID")
			if len(args) < 3 {
				cmdUsersRulesList(args[1])
				return
			}
			switch args[2] {
			case "add":
				cmdUsersRulesAdd(args[1], args[3:])
			case "remove", "rm":
				requireArg(args, 3, "rule ID")
				cmdUsersRulesRemove(args[1], args[3])
			default:
				fmt.Fprintf(os.Stderr, "Unknown rules subcommand: %s\n", args[2])
				os.Exit(1)
			}
		case "config":
			requireArg(args, 1, "user ID")
			cmdUsersConfig(args[1])
		case "regen":
			requireArg(args, 1, "user ID")
			cmdUsersRegen(args[1])
		default:
			cmdUsersGet(args[0])
		}
	case "api":
		requireAPI()
		cmdAPI(args)
	case "security":
		requireAPI()
		if len(args) == 0 {
			cmdSecurityAll()
		} else {
			cmdSecurityNode(args[0])
		}
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`vpnctl — VPN management CLI

Usage: vpnctl <command> [subcommand] [args]

Local commands (standalone mode — no API required):
  peer add <name>        Add a new peer (generates keys, shows config)
  peer remove <name>     Remove a peer
  peer list              List all configured peers
  config show <name>     Show WireGuard client config for a peer
  qr <name>              Show QR code for a peer's config

Remote commands (managed mode — requires VPN_API_URL):
  status                 Show system overview
  nodes                  List all nodes
  nodes get <id>         Show node details
  nodes add              Register a new node
  nodes bw <id>          Show bandwidth for a node
  users                  List all users
  users get <id|email>   Show user details
  users create           Create a new user
  users delete <id>      Delete a user
  users rules <id>       List network bypass rules
  users rules <id> add   Add a bypass rule (--name, --network)
  users rules <id> rm    Remove a bypass rule
  users config <id>      Regenerate WireGuard client config
  users regen <id>       Regenerate config + new onboarding link
  api <METHOD> <path>    Call any API endpoint (e.g. api GET /api/nodes)
      [--data <json>]    Request body (for POST/PUT/PATCH)
  security               Show security status for all nodes
  security <node_id>     Show security status for a specific node

Environment:
  VPN_CONFIG             Path to peer config file (default: /etc/vpn/peers.json)
  VPN_API_URL            API base URL (for remote commands)
  VPN_ADMIN_TOKEN        Admin authentication token (for remote commands)`)
}

// requireAPI ensures VPN_API_URL is set for remote commands.
func requireAPI() {
	if apiURL == "" {
		fatal("VPN_API_URL not set. Remote commands require a control plane API.\nFor local peer management, use: vpnctl peer add <name>")
	}
}

// === Local (standalone) commands ===

func loadConfig() *config.Config {
	cfg, err := config.Load(configPath)
	if err != nil {
		fatal("Failed to load config %s: %v", configPath, err)
	}
	return cfg
}

func cmdPeerAdd(name string) {
	cfg := loadConfig()

	// Generate WireGuard keypair locally. Private key never leaves this machine.
	keys, err := wireguard.GenerateKeyPair()
	if err != nil {
		fatal("Failed to generate WireGuard keys: %v", err)
	}

	peer, address, err := cfg.AddPeer(name, keys.PublicKey)
	if err != nil {
		fatal("Failed to add peer: %v", err)
	}

	fmt.Printf("Peer added: %s\n", name)
	fmt.Printf("Address:    %s\n", address)
	fmt.Printf("Public key: %s\n", peer.PublicKey)

	// Generate and display client config.
	clientAddr := strings.TrimSuffix(address, "/32") + "/24"
	clientConfig, err := wireguard.GeneratePeerConfig(wireguard.PeerConfig{
		PrivateKey: keys.PrivateKey,
		Address:    clientAddr,
		DNS:        cfg.Server.DNS,
		PublicKey:  cfg.Server.PublicKey,
		Endpoint:   cfg.Server.Endpoint,
		AllowedIPs: "0.0.0.0/0",
	})
	if err != nil {
		fatal("Failed to generate client config: %v", err)
	}

	fmt.Println("\n--- WireGuard Client Config ---")
	fmt.Println(clientConfig)
	fmt.Println("--- End Config ---")
	fmt.Println("\nSave this config to a .conf file and import into WireGuard.")
	fmt.Println("The agent will automatically pick up the new peer.")

	// Print QR code hint.
	fmt.Printf("\nTo show a QR code: vpnctl qr %s\n", name)
	fmt.Println("(Note: the private key is shown above only once. Save it now.)")
}

func cmdPeerRemove(name string) {
	cfg := loadConfig()
	peer, err := cfg.RemovePeer(name)
	if err != nil {
		fatal("Failed to remove peer: %v", err)
	}
	fmt.Printf("Peer removed: %s (%s)\n", name, peer.AllowedIPs)
	fmt.Println("The agent will automatically remove the peer from WireGuard.")
}

func cmdPeerList() {
	cfg := loadConfig()
	peers := cfg.ListPeers()

	if len(peers) == 0 {
		fmt.Println("No peers configured.")
		fmt.Println("Add one with: vpnctl peer add <name>")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDRESS\tPUBLIC KEY\tCREATED")
	fmt.Fprintln(w, "----\t-------\t----------\t-------")
	for _, p := range peers {
		created := p.CreatedAt.Format("2006-01-02 15:04")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			p.Name, p.AllowedIPs, truncate(p.PublicKey, 20), created)
	}
	w.Flush()
}

func cmdConfigShow(name string) {
	cfg := loadConfig()
	peer := cfg.GetPeer(name)
	if peer == nil {
		fatal("Peer not found: %s", name)
	}

	if cfg.Server.PublicKey == "" {
		fatal("Server public key not set. Run the agent first to auto-detect, or set it in %s", configPath)
	}

	// We can't show the private key here — it was only displayed at creation time.
	// Show a placeholder and instruct the user.
	clientAddr := strings.TrimSuffix(peer.AllowedIPs, "/32") + "/24"
	clientConfig, err := wireguard.GeneratePeerConfig(wireguard.PeerConfig{
		PrivateKey: "<YOUR_PRIVATE_KEY>",
		Address:    clientAddr,
		DNS:        cfg.Server.DNS,
		PublicKey:  cfg.Server.PublicKey,
		Endpoint:   cfg.Server.Endpoint,
		AllowedIPs: "0.0.0.0/0",
	})
	if err != nil {
		fatal("Failed to generate config: %v", err)
	}

	fmt.Println(clientConfig)
	fmt.Println("Note: Replace <YOUR_PRIVATE_KEY> with the private key shown when the peer was created.")
}

func cmdQR(name string) {
	cfg := loadConfig()
	peer := cfg.GetPeer(name)
	if peer == nil {
		fatal("Peer not found: %s", name)
	}

	if cfg.Server.PublicKey == "" {
		fatal("Server public key not set. Run the agent first to auto-detect, or set it in %s", configPath)
	}

	// Same limitation — we don't store the private key.
	clientAddr := strings.TrimSuffix(peer.AllowedIPs, "/32") + "/24"
	clientConfig, err := wireguard.GeneratePeerConfig(wireguard.PeerConfig{
		PrivateKey: "<YOUR_PRIVATE_KEY>",
		Address:    clientAddr,
		DNS:        cfg.Server.DNS,
		PublicKey:  cfg.Server.PublicKey,
		Endpoint:   cfg.Server.Endpoint,
		AllowedIPs: "0.0.0.0/0",
	})
	if err != nil {
		fatal("Failed to generate config: %v", err)
	}

	qr, err := qrcode.New(clientConfig, qrcode.Medium)
	if err != nil {
		fatal("Failed to generate QR code: %v", err)
	}

	fmt.Println(qr.ToSmallString(false))
	fmt.Println("Note: Replace <YOUR_PRIVATE_KEY> in the config with the private key shown when the peer was created.")
}

// === Remote (managed/API) commands ===

func cmdStatus() {
	nodes := apiGet("/api/nodes")
	users := apiGet("/api/users")

	var nodeList []map[string]any
	var userList []map[string]any
	json.Unmarshal(nodes, &nodeList)
	json.Unmarshal(users, &userList)

	fmt.Println("=== VPN Control Plane ===")
	fmt.Printf("API:    %s\n", apiURL)
	fmt.Printf("Nodes:  %d\n", len(nodeList))
	fmt.Printf("Users:  %d\n\n", len(userList))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tLOCATION\tIP\tOWNER\tSTATUS")
	fmt.Fprintln(w, "----\t--------\t--\t-----\t------")
	for _, n := range nodeList {
		ownerID := "-"
		if v, ok := n["owner_id"].(string); ok && v != "" {
			ownerID = truncate(v, 12)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			n["id"], n["region"], n["ip"],
			ownerID, n["status"])
	}
	w.Flush()

	if len(userList) > 0 {
		fmt.Println()
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "USER\tEMAIL\tNODE\tPLAN\tBANDWIDTH")
		fmt.Fprintln(w, "----\t-----\t----\t----\t---------")
		for _, u := range userList {
			bwUsed := int64(u["bandwidth_used"].(float64))
			bwLimit := int64(u["bandwidth_limit"].(float64))
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s / %s\n",
				truncate(u["id"].(string), 12), u["email"], u["assigned_node_id"],
				u["plan"], humanBytes(bwUsed), humanBytes(bwLimit))
		}
		w.Flush()
	}
}

// --- Nodes ---

func cmdNodesList() {
	data := apiGet("/api/nodes")
	var nodes []map[string]any
	json.Unmarshal(data, &nodes)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tREGION\tOWNER\tSTATUS")
	fmt.Fprintln(w, "--\t--\t------\t-----\t------")
	for _, n := range nodes {
		ownerID := "-"
		if v, ok := n["owner_id"].(string); ok && v != "" {
			ownerID = truncate(v, 12)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			n["id"], n["ip"], n["region"],
			ownerID, n["status"])
	}
	w.Flush()
}

func cmdNodesGet(id string) {
	data := apiGet("/api/nodes/" + id)
	printJSON(data)
}

func cmdNodesAdd(args []string) {
	var id, name, ip, region, pubkey string
	for i := 0; i < len(args)-1; i += 2 {
		switch args[i] {
		case "--id":
			id = args[i+1]
		case "--name":
			name = args[i+1]
		case "--ip":
			ip = args[i+1]
		case "--region":
			region = args[i+1]
		case "--pubkey":
			pubkey = args[i+1]
		}
	}
	if id == "" || ip == "" {
		fmt.Fprintln(os.Stderr, "Usage: vpnctl nodes add --id <id> --ip <ip> [--name <name>] [--region <region>] [--pubkey <key>]")
		os.Exit(1)
	}
	if name == "" {
		name = id
	}

	payload := map[string]string{
		"id": id, "name": name, "ip": ip, "region": region, "public_key": pubkey,
	}
	data := apiPost("/api/nodes", payload)

	var result map[string]any
	json.Unmarshal(data, &result)
	fmt.Printf("Node registered: %s\n", id)
	if t, ok := result["agent_token"]; ok {
		fmt.Printf("Agent token:     %s\n", t)
		fmt.Println("\nAdd to the node's /opt/vpn-agent/.env:")
		fmt.Printf("  AGENT_TOKEN=%s\n", t)
	}
}

func cmdNodesBandwidth(id string) {
	data := apiGet("/api/nodes/" + id + "/bandwidth")
	var peers []map[string]any
	json.Unmarshal(data, &peers)

	if len(peers) == 0 {
		fmt.Println("No bandwidth data for this node.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PEER\tRECEIVED\tSENT\tLAST UPDATED")
	fmt.Fprintln(w, "----\t--------\t----\t------------")
	for _, p := range peers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			truncate(p["public_key"].(string), 20),
			humanBytes(int64(p["total_received"].(float64))),
			humanBytes(int64(p["total_sent"].(float64))),
			p["last_updated"])
	}
	w.Flush()
}

// --- Users ---

func cmdUsersList() {
	data := apiGet("/api/users")
	var users []map[string]any
	json.Unmarshal(data, &users)

	if len(users) == 0 {
		fmt.Println("No users.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tEMAIL\tNODE\tPLAN\tBANDWIDTH\tCREATED")
	fmt.Fprintln(w, "--\t-----\t----\t----\t---------\t-------")
	for _, u := range users {
		bwUsed := int64(u["bandwidth_used"].(float64))
		bwLimit := int64(u["bandwidth_limit"].(float64))
		created := ""
		if c, ok := u["created_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, c); err == nil {
				created = t.Format("2006-01-02")
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s / %s\t%s\n",
			truncate(u["id"].(string), 12), u["email"], u["assigned_node_id"],
			u["plan"], humanBytes(bwUsed), humanBytes(bwLimit), created)
	}
	w.Flush()
}

func cmdUsersGet(idOrEmail string) {
	data := apiGetMaybe("/api/users/" + idOrEmail)
	if data != nil {
		printJSON(data)
		return
	}
	listData := apiGet("/api/users")
	var users []map[string]any
	json.Unmarshal(listData, &users)
	for _, u := range users {
		if u["email"] == idOrEmail {
			b, _ := json.MarshalIndent(u, "", "  ")
			fmt.Println(string(b))
			return
		}
	}
	fmt.Fprintf(os.Stderr, "User not found: %s\n", idOrEmail)
	os.Exit(1)
}

func cmdUsersCreate(args []string) {
	var email, plan, nodeID string
	for i := 0; i < len(args)-1; i += 2 {
		switch args[i] {
		case "--email":
			email = args[i+1]
		case "--plan":
			plan = args[i+1]
		case "--node":
			nodeID = args[i+1]
		}
	}
	if email == "" {
		fmt.Fprintln(os.Stderr, "Usage: vpnctl users create --email <email> [--plan standard|premium] [--node <node_id>]")
		os.Exit(1)
	}

	payload := map[string]string{"email": email}
	if plan != "" {
		payload["plan"] = plan
	}
	if nodeID != "" {
		payload["node_id"] = nodeID
	}

	data := apiPost("/api/users", payload)

	var result map[string]any
	json.Unmarshal(data, &result)

	if user, ok := result["user"].(map[string]any); ok {
		fmt.Printf("User created: %s (%s)\n", user["email"], truncate(user["id"].(string), 12))
		fmt.Printf("Node:         %s\n", user["assigned_node_id"])
		fmt.Printf("Address:      %s\n", user["address"])
		fmt.Printf("Plan:         %s\n", user["plan"])
		fmt.Printf("Bandwidth:    %s\n", humanBytes(int64(user["bandwidth_limit"].(float64))))
	}

	if onboardURL, ok := result["onboarding_url"].(string); ok {
		fmt.Printf("\nOnboarding URL: %s%s\n", apiURL, onboardURL)
		fmt.Println("Send this link to the user to set up their VPN.")
	}

	if cfg, ok := result["client_config"].(string); ok {
		fmt.Println("\n--- Client Config ---")
		fmt.Println(cfg)
		fmt.Println("--- End Config ---")
		fmt.Println("\nSave the config above to a .conf file and import into WireGuard.")
	}
}

func cmdUsersDelete(id string) {
	req, _ := http.NewRequest("DELETE", apiURL+"/api/users/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		fatal("API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		fmt.Printf("User %s deleted.\n", id)
	} else if resp.StatusCode == 404 {
		fmt.Fprintf(os.Stderr, "User not found: %s\n", id)
		os.Exit(1)
	} else {
		body, _ := io.ReadAll(resp.Body)
		fatal("Delete failed (%d): %s", resp.StatusCode, string(body))
	}
}

// --- User Rules ---

func cmdUsersRulesList(userID string) {
	data := apiGet("/api/users/" + userID + "/rules")
	var rules []map[string]any
	json.Unmarshal(data, &rules)

	if len(rules) == 0 {
		fmt.Println("No network rules for this user.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tNETWORK\tACTION")
	fmt.Fprintln(w, "--\t----\t-------\t------")
	for _, r := range rules {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			truncate(r["id"].(string), 12), r["name"], r["network"], r["action"])
	}
	w.Flush()
}

func cmdUsersRulesAdd(userID string, args []string) {
	var name, network string
	for i := 0; i < len(args)-1; i += 2 {
		switch args[i] {
		case "--name":
			name = args[i+1]
		case "--network":
			network = args[i+1]
		}
	}
	if name == "" || network == "" {
		fmt.Fprintln(os.Stderr, "Usage: vpnctl users rules <user_id> add --name <name> --network <cidr>")
		os.Exit(1)
	}

	payload := map[string]string{
		"name":    name,
		"network": network,
		"action":  "bypass",
	}
	data := apiPost("/api/users/"+userID+"/rules", payload)

	var rule map[string]any
	json.Unmarshal(data, &rule)
	fmt.Printf("Rule added: %s (%s bypass %s)\n", truncate(rule["id"].(string), 12), name, network)
}

func cmdUsersRulesRemove(userID, ruleID string) {
	req, _ := http.NewRequest("DELETE", apiURL+"/api/users/"+userID+"/rules/"+ruleID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		fatal("API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		fmt.Printf("Rule %s removed.\n", ruleID)
	} else if resp.StatusCode == 404 {
		fmt.Fprintf(os.Stderr, "Rule not found: %s\n", ruleID)
		os.Exit(1)
	} else {
		body, _ := io.ReadAll(resp.Body)
		fatal("Delete failed (%d): %s", resp.StatusCode, string(body))
	}
}

// --- User Regen ---

func cmdUsersRegen(id string) {
	data := apiPostEmpty("/api/users/" + id + "/regen-config")

	var result map[string]any
	json.Unmarshal(data, &result)

	if onboardURL, ok := result["onboarding_url"].(string); ok {
		fmt.Printf("New onboarding URL: %s%s\n", apiURL, onboardURL)
		fmt.Println("Send this link to the user to set up their VPN.")
	}

	if cfg, ok := result["client_config"].(string); ok {
		fmt.Println("\n--- Client Config ---")
		fmt.Println(cfg)
		fmt.Println("--- End Config ---")
	}
}

// --- User Config ---

func cmdUsersConfig(userID string) {
	data := apiGet("/api/users/" + userID + "/config")
	var result map[string]any
	json.Unmarshal(data, &result)

	if cfg, ok := result["config"].(string); ok {
		fmt.Println(cfg)
	}
}

// --- Generic API ---

func cmdAPI(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: vpnctl api <METHOD> <path> [--data <json>]")
		os.Exit(1)
	}

	method := strings.ToUpper(args[0])
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH":
	default:
		fatal("Invalid HTTP method: %s (must be GET, POST, PUT, DELETE, or PATCH)", method)
	}

	path := args[1]
	if err := validateAPIPath(path); err != nil {
		fatal("Invalid path: %v", err)
	}

	var body string
	for i := 2; i < len(args)-1; i++ {
		if args[i] == "--data" {
			body = args[i+1]
			break
		}
	}

	if body != "" {
		if !json.Valid([]byte(body)) {
			fatal("Invalid JSON in --data: %s", body)
		}
	}

	u, err := url.JoinPath(apiURL, path)
	if err != nil {
		fatal("Failed to build URL: %v", err)
	}

	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, u, reqBody)
	if err != nil {
		fatal("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		fatal("API request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if len(respBody) > 0 {
		printJSON(respBody)
	}

	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "\nHTTP %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		os.Exit(1)
	}
}

func validateAPIPath(path string) error {
	if strings.Contains(path, "://") {
		return fmt.Errorf("absolute URLs are not allowed — use a path like /api/nodes")
	}
	if !strings.HasPrefix(path, "/api/") {
		return fmt.Errorf("path must start with /api/ (got %q)", path)
	}
	return nil
}

// --- HTTP helpers ---

func apiGet(path string) []byte {
	data := apiGetMaybe(path)
	if data == nil {
		fatal("Not found: %s", path)
	}
	return data
}

func apiGetMaybe(path string) []byte {
	req, _ := http.NewRequest("GET", apiURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		fatal("API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil
	}
	if resp.StatusCode == 401 {
		fatal("Unauthorized. Set VPN_ADMIN_TOKEN.")
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		fatal("API error (%d): %s", resp.StatusCode, string(body))
	}
	return body
}

func apiPostEmpty(path string) []byte {
	req, _ := http.NewRequest("POST", apiURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		fatal("API request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 401 {
		fatal("Unauthorized. Set VPN_ADMIN_TOKEN.")
	}
	if resp.StatusCode >= 400 {
		fatal("API error (%d): %s", resp.StatusCode, string(respBody))
	}
	return respBody
}

func apiPost(path string, payload any) []byte {
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", apiURL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		fatal("API request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 401 {
		fatal("Unauthorized. Set VPN_ADMIN_TOKEN.")
	}
	if resp.StatusCode >= 400 {
		fatal("API error (%d): %s", resp.StatusCode, string(respBody))
	}
	return respBody
}

// --- Formatting helpers ---

func printJSON(data []byte) {
	var v any
	json.Unmarshal(data, &v)
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<40:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(1<<40))
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func requireArg(args []string, idx int, name string) {
	if len(args) <= idx {
		fmt.Fprintf(os.Stderr, "Missing argument: %s\n", name)
		os.Exit(1)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// --- Security ---

func cmdSecurityAll() {
	data := apiGet("/api/nodes")
	var nodes []map[string]any
	json.Unmarshal(data, &nodes)

	for _, n := range nodes {
		nodeID := n["id"].(string)
		fmt.Printf("=== %s (%s) ===\n", nodeID, n["ip"])
		cmdSecurityNode(nodeID)
		fmt.Println()
	}
}

func cmdSecurityNode(nodeID string) {
	data := apiGetMaybe("/api/nodes/" + nodeID + "/security")
	if data == nil {
		fmt.Println("  Could not retrieve security status")
		return
	}

	var s map[string]any
	json.Unmarshal(data, &s)

	check := func(ok bool) string {
		if ok {
			return "OK"
		}
		return "FAIL"
	}

	if tls, ok := s["tls"].(map[string]any); ok {
		enabled, _ := tls["enabled"].(bool)
		fmt.Printf("  TLS:                %s\n", check(enabled))
	}

	if f2b, ok := s["fail2ban"].(map[string]any); ok {
		active, _ := f2b["active"].(bool)
		banned := int(f2b["currently_banned"].(float64))
		totalBanned := int(f2b["total_banned"].(float64))
		fmt.Printf("  Fail2Ban:           %s  (banned: %d, total: %d)\n", check(active), banned, totalBanned)
	}

	if ssh, ok := s["ssh"].(map[string]any); ok {
		rootHardened, _ := ssh["root_login_hardened"].(bool)
		pwDisabled, _ := ssh["password_auth_disabled"].(bool)
		maxAuth := int(ssh["max_auth_tries"].(float64))
		fmt.Printf("  SSH Root Login:     %s  (%s)\n", check(rootHardened), ssh["permit_root_login"])
		fmt.Printf("  SSH Password Auth:  %s\n", check(pwDisabled))
		fmt.Printf("  SSH Max Auth Tries: %d\n", maxAuth)
	}

	if uu, ok := s["unattended_upgrades"].(map[string]any); ok {
		active, _ := uu["active"].(bool)
		fmt.Printf("  Auto Updates:       %s\n", check(active))
	}

	if fw, ok := s["firewall"].(map[string]any); ok {
		active, _ := fw["active"].(bool)
		rules, _ := fw["rules"].([]any)
		fmt.Printf("  Firewall:           %s  (%d rules)\n", check(active), len(rules))
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func isLocalhost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
