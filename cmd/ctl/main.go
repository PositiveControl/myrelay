package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

var (
	apiURL string
	token  string
	client = &http.Client{Timeout: 10 * time.Second}
)

func main() {
	apiURL = envOrDefault("VPN_API_URL", "http://localhost:8080")
	token = envOrDefault("VPN_ADMIN_TOKEN", "")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "status":
		cmdStatus()
	case "nodes":
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
		default:
			cmdUsersGet(args[0])
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
	fmt.Println(`vpnctl — VPN control plane CLI

Usage: vpnctl <command> [subcommand] [args]

Commands:
  status                 Show system overview
  nodes                  List all nodes
  nodes get <id>         Show node details
  nodes add              Register a new node (interactive)
  nodes bw <id>          Show bandwidth for a node
  users                  List all users
  users get <id|email>   Show user details
  users create           Create a new user (interactive)
  users delete <id>      Delete a user

Environment:
  VPN_API_URL            API base URL (default: http://localhost:8080)
  VPN_ADMIN_TOKEN        Admin authentication token`)
}

// --- Status ---

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

	// Node summary
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tLOCATION\tIP\tPEERS\tSTATUS")
	fmt.Fprintln(w, "----\t--------\t--\t-----\t------")
	for _, n := range nodeList {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.0f/%.0f\t%s\n",
			n["id"], n["region"], n["ip"],
			n["current_peers"], n["max_peers"], n["status"])
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
	fmt.Fprintln(w, "ID\tIP\tREGION\tPEERS\tSTATUS")
	fmt.Fprintln(w, "--\t--\t------\t-----\t------")
	for _, n := range nodes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.0f/%.0f\t%s\n",
			n["id"], n["ip"], n["region"],
			n["current_peers"], n["max_peers"], n["status"])
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
	// Try by ID first
	data := apiGetMaybe("/api/users/" + idOrEmail)
	if data != nil {
		printJSON(data)
		return
	}
	// Search by email in the list
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

	if config, ok := result["client_config"].(string); ok {
		fmt.Println("\n--- Client Config ---")
		fmt.Println(config)
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

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Ensure unused import doesn't cause issues
var _ = strings.TrimSpace
