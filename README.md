# VPN

A self-hosted WireGuard VPN toolkit. Set up a private VPN server, add peers with one command, and hand out QR codes to your family — no account system, no cloud dependency, no subscription.

## Quick Start

**On your server** (Ubuntu/Debian with a public IP):

```bash
# 1. Install WireGuard
apt install wireguard wireguard-tools

# 2. Set up the WireGuard interface
# (see "Server Setup" below, or use the Hetzner example in examples/hetzner/)

# 3. Build and install
make build-agent build-ctl
cp bin/agent bin/vpnctl /usr/local/bin/

# 4. Start the agent
agent -mode standalone -interface wg0 &

# 5. Add your first peer
vpnctl peer add my-phone
```

That last command generates a WireGuard keypair, allocates an IP, and prints the client config. Scan the QR code or paste the config into the WireGuard app — you're connected.

## How It Works

```
┌─────────────┐         ┌──────────────────────────────┐
│  vpnctl     │ writes  │  /etc/vpn/peers.json         │
│  (CLI)      │───────→ │  (peer config file)          │
└─────────────┘         └──────────────┬───────────────┘
                                       │ watches
                        ┌──────────────▼───────────────┐
                        │  agent                       │
                        │  (standalone mode)            │
                        │  - syncs WireGuard peers      │
                        │  - monitors bandwidth         │
                        └──────────────────────────────┘
```

The CLI manages a JSON config file. The agent watches it and keeps WireGuard in sync. No database, no API server, no remote calls.

## CLI Commands

### Local commands (standalone mode — no API required)

```bash
vpnctl peer add <name>       # Add peer, generate keys, show config + QR hint
vpnctl peer remove <name>    # Remove a peer
vpnctl peer list             # List all peers
vpnctl config show <name>    # Show WireGuard client config
vpnctl qr <name>             # Display QR code in terminal
```

### Remote commands (managed mode — requires a control plane API)

```bash
vpnctl status                # System overview
vpnctl nodes list            # List VPN nodes
vpnctl users create --email user@example.com
vpnctl users config <id>     # Show client config
vpnctl security              # Node security audit
```

Remote commands require `VPN_API_URL` and `VPN_ADMIN_TOKEN` environment variables.

## Server Setup

### Option A: Quick manual setup

```bash
# Install WireGuard
apt update && apt install -y wireguard wireguard-tools

# Enable IP forwarding
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wg.conf
sysctl --system

# Generate server keys
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
chmod 600 /etc/wireguard/server.key

# Create WireGuard config
IFACE=$(ip route show default | awk '{print $5}' | head -1)
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/server.key)
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $IFACE -j MASQUERADE
EOF
chmod 600 /etc/wireguard/wg0.conf

# Start WireGuard
systemctl enable --now wg-quick@wg0
```

### Option B: Hetzner Cloud with Terraform

```bash
cd examples/hetzner
export HCLOUD_TOKEN="your-token"
terraform init && terraform apply -var ssh_key_name="your-key"
```

This provisions a server with WireGuard pre-configured via cloud-init.

## Agent

The agent runs on the VPN server and keeps WireGuard peers in sync with the config file.

### Standalone mode (default)

```bash
agent -mode standalone -interface wg0
```

Watches `/etc/vpn/peers.json`, auto-detects the server's public key and endpoint, and syncs WireGuard whenever the config changes.

### Managed mode

For multi-node deployments with a central control plane:

```bash
agent -mode managed -node-id vpn-us-west -token <token> -api https://api.example.com:8080
```

### Configuration

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `-mode` | `AGENT_MODE` | `standalone` | `standalone` or `managed` |
| `-config` | `CONFIG_PATH` | `/etc/vpn/peers.json` | Peer config file path |
| `-interface` | `WG_INTERFACE` | `wg0` | WireGuard interface |
| `-listen` | `AGENT_LISTEN` | `:8081` | HTTP status endpoint |
| `-watch` | — | `2s` | Config watch interval |
| `-poll` | — | `30s` | Bandwidth poll interval |
| `-api` | `API_URL` | — | Control plane URL (managed) |
| `-node-id` | `NODE_ID` | — | Node ID (managed) |
| `-token` | `AGENT_TOKEN` | — | Auth token |

## Features

- **Single-command peer management** — `vpnctl peer add` handles key generation, IP allocation, and config output
- **Client-side key generation** — Private keys are generated on the CLI machine and never stored on the server
- **Split tunneling** — Bypass rules to exclude specific networks from the VPN tunnel
- **Bandwidth monitoring** — Per-peer traffic stats via `wg show`
- **QR codes** — Terminal QR output for mobile onboarding
- **TUI dashboard** — Real-time monitoring with sortable tables and node cards

## Building

```bash
make all          # Build agent, vpnctl, vpn-tui, and API server
make build-agent  # Build just the agent
make build-ctl    # Build just the CLI
make test         # Run tests with race detection
make lint         # go vet + staticcheck
```

Requires Go 1.24+ and WireGuard tools installed.

## Project Structure

```
cmd/agent/             Agent binary (standalone + managed modes)
cmd/ctl/               CLI tool (vpnctl)
cmd/tui/               TUI dashboard
cmd/api/               Control plane API server (for managed deployments)
internal/config/       Local peer config file management
internal/wireguard/    WireGuard key generation, peer sync, split tunneling
internal/bandwidth/    Per-peer bandwidth monitoring
internal/api/          API server, handlers, auth, onboarding
internal/db/           SQLite database (managed mode)
internal/validate/     Input validation
examples/hetzner/      Single-node Terraform example
scripts/               Node setup and deployment scripts
```

## Security

- Private keys are generated client-side and never sent to or stored on the server
- WireGuard keys and CIDR inputs are validated before use
- Agent endpoints require bearer token authentication with constant-time comparison
- TLS support with auto-generated certificates from an internal CA
- WIP

## License

[MIT](LICENSE)
