# VPN Service

A WireGuard-based VPN service with a control plane API and per-node agents, deployed on Hetzner Cloud via Terraform.

## Architecture

- **Control Plane API** (`cmd/api`): HTTP API for managing users and VPN nodes. Handles user registration, key generation, peer assignment, and bandwidth tracking.
- **Node Agent** (`cmd/agent`): Runs on each VPN node. Applies WireGuard configuration changes, reports bandwidth usage back to the control plane.
- **Terraform** (`terraform/`): Provisions Hetzner CX22 instances with cloud-init bootstrapping.

## Prerequisites

- Go 1.22+
- Terraform 1.5+
- WireGuard tools (`wg`, `wg-quick`) installed locally for development
- A Hetzner Cloud API token

## Quick Start

```bash
# Build binaries
make build-api
make build-agent

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
# Format code
make fmt

# Run linter
make lint

# Run API server locally
./bin/api -addr :8080

# Run agent locally (requires root for WireGuard)
sudo ./bin/agent -api http://localhost:8080 -interface wg0
```

## Deployment

After provisioning nodes with Terraform:

```bash
# Deploy agent binary to all nodes
./scripts/deploy-agent.sh
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/users | Create a new user |
| GET | /api/users | List all users |
| GET | /api/users/{id} | Get user by ID |
| DELETE | /api/users/{id} | Delete a user |
| GET | /api/nodes | List all nodes |
| GET | /api/nodes/{id} | Get node by ID |
| POST | /api/nodes/{id}/sync | Trigger config sync on a node |

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDR` | API server listen address | `:8080` |
| `DATA_DIR` | Directory for persistent data | `./data` |
| `HCLOUD_TOKEN` | Hetzner Cloud API token | — |

## License

Private. All rights reserved.
