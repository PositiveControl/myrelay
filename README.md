# VPN Service

A WireGuard-based VPN service with a control plane API, per-node agents, CLI, and terminal UI dashboard. Deployed on Hetzner Cloud via Terraform across multiple regions.

## Architecture

- **Control Plane API** (`cmd/api`): HTTP API for managing users and VPN nodes. Handles user registration, key generation, peer assignment, bandwidth tracking, onboarding, and bypass rules.
- **Node Agent** (`cmd/agent`): Runs on each VPN node. Applies WireGuard configuration changes, monitors per-peer bandwidth, and reports usage back to the control plane.
- **CLI** (`cmd/ctl`): Command-line tool (`vpnctl`) for managing nodes, users, bypass rules, and viewing system status.
- **TUI Dashboard** (`cmd/tui`): Terminal UI with real-time stats, node cards, sortable tables, and detail modals.
- **Terraform** (`terraform/`): Provisions Hetzner Cloud instances across US, EU, and APAC regions with cloud-init bootstrapping.

## Features

- **Multi-region deployment** — US West (Oregon), EU (Finland), APAC (Singapore) out of the box
- **Subscription plans** — Standard (100 GB/month) and Premium (1 TB/month) with automatic bandwidth enforcement
- **Split tunneling** — Predefined bypass rules for Apple, Netflix, Spotify, and YouTube with per-user overrides
- **Auto node assignment** — Users are assigned to the least-loaded node with automatic IP allocation
- **Client onboarding** — Device-aware onboarding pages with QR codes for mobile and direct config download
- **Per-peer bandwidth monitoring** — Real-time tracking with cumulative and interval stats
- **Admin and per-node authentication** — Bearer tokens with constant-time comparison

## Prerequisites

- Go 1.24+
- Terraform 1.5+
- WireGuard tools (`wg`, `wg-quick`) installed locally for development
- A Hetzner Cloud API token

## Quick Start

```bash
# Build all binaries (api, agent, vpnctl, vpn-tui)
make all

# Run tests
make test

# Deploy infrastructure
export HCLOUD_TOKEN="your-token-here"
make tf-init
make tf-plan
make tf-apply
```

## Development

```bash
# Format Go and Terraform code
make fmt

# Run linter (vet + staticcheck)
make lint

# Run API server locally
./bin/api -addr :8080 -admin-token mytoken -db vpn.db

# Run agent locally (requires root for WireGuard)
sudo ./bin/agent -api http://localhost:8080 -node-id node1 -token agenttoken -interface wg0

# CLI
export VPN_API_URL=http://localhost:8080
export VPN_ADMIN_TOKEN=mytoken
./bin/vpnctl status
./bin/vpnctl nodes list
./bin/vpnctl users create --email user@example.com --plan standard

# TUI dashboard
./bin/vpn-tui
```

## Deployment

After provisioning nodes with Terraform:

```bash
# Deploy agent binary to all nodes
./scripts/deploy-agent.sh
```

The `scripts/setup-node.sh` cloud-init script handles initial node setup: installs WireGuard, enables IP forwarding, configures iptables NAT, sets up UFW (SSH, WireGuard 51820, Agent 8081), and creates the systemd service.

## API Endpoints

### Public

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/health | Health check |
| GET | /onboard/{token} | Device-aware onboarding page |
| GET | /onboard/{token}/config | Download WireGuard config |
| GET | /onboard/{token}/qr | QR code PNG for mobile |

### Admin (Bearer token required)

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/users | Create a new user |
| GET | /api/users | List all users |
| GET | /api/users/{id} | Get user by ID |
| DELETE | /api/users/{id} | Delete user and remove peer |
| GET | /api/users/{id}/config | Get WireGuard config |
| POST | /api/users/{id}/regen-config | Regenerate config |
| GET | /api/users/{id}/rules | List user network rules |
| POST | /api/users/{id}/rules | Add network rule |
| DELETE | /api/users/{id}/rules/{ruleId} | Remove network rule |
| GET | /api/users/{id}/bypass | Get user bypass config |
| PUT | /api/users/{id}/bypass | Set bypass override |
| GET | /api/bypass/rules | List available bypass rules |
| POST | /api/nodes | Register a node |
| GET | /api/nodes | List all nodes |
| GET | /api/nodes/{id} | Get node details |
| POST | /api/nodes/{id}/sync | Trigger config sync |
| GET | /api/nodes/{id}/bandwidth | Get peer bandwidth stats |

### Node Agent

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/nodes/{id}/bandwidth | Report bandwidth data |

## Configuration

### API Server

| Flag / Variable | Description | Default |
|-----------------|-------------|---------|
| `-addr` / `LISTEN_ADDR` | HTTP listen address | `:8080` |
| `-db` / `DB_PATH` | SQLite database path | `vpn.db` |
| `-admin-token` / `ADMIN_TOKEN` | Admin auth token | auto-generated |

### Node Agent

| Flag / Variable | Description | Default |
|-----------------|-------------|---------|
| `-api` / `API_URL` | Control plane URL | `http://localhost:8080` |
| `-node-id` / `NODE_ID` | Node identifier | required |
| `-token` / `AGENT_TOKEN` | Agent auth token | — |
| `-interface` / `WG_INTERFACE` | WireGuard interface | `wg0` |
| `-listen` / `AGENT_LISTEN` | Agent HTTP listen address | `:8081` |
| `-poll` | Bandwidth poll interval | `30s` |
| `-report` | Report interval to control plane | `60s` |

### CLI / TUI

| Variable | Description | Default |
|----------|-------------|---------|
| `VPN_API_URL` | API server URL | `http://localhost:8080` |
| `VPN_ADMIN_TOKEN` | Admin auth token | — |

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make all` | Build all binaries |
| `make build-api` | Build API server |
| `make build-agent` | Build node agent |
| `make build-ctl` | Build CLI tool |
| `make build-tui` | Build TUI dashboard |
| `make test` | Run tests with race detection |
| `make fmt` | Format Go and Terraform code |
| `make lint` | Run vet and staticcheck |
| `make clean` | Remove build artifacts |
| `make tf-init` | Initialize Terraform |
| `make tf-plan` | Plan infrastructure changes |
| `make tf-apply` | Apply infrastructure changes |
| `make tf-destroy` | Destroy infrastructure |

## License

Private. All rights reserved.
