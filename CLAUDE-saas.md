# MyRelay SaaS

The managed VPN service. Customers pay per exit node, get provisioned infrastructure, and manage peers via web dashboard or onboarding links.

## What's SaaS-only

| Path | Purpose |
|------|---------|
| `cmd/api/` | Control plane API server (user/node CRUD, onboarding, bandwidth tracking) |
| `internal/api/server.go` | HTTP server, routing, TLS, logging middleware |
| `internal/api/auth.go` | Admin + per-node token authentication |
| `internal/api/handlers/users.go` | User creation, deletion, config generation, bypass rules |
| `internal/api/handlers/nodes.go` | Node registration, bandwidth reporting, security status |
| `internal/api/onboard.go` | Device-aware onboarding pages, QR codes, config download |
| `internal/agent/client.go` | API→node agent HTTP client (push peers, get security) |
| `internal/db/db.go` | SQLite: nodes, users, tokens, IP counter, onboarding, network rules |
| `terraform/` | Multi-node Hetzner Cloud infra (3 regions, firewalls) |
| `scripts/deploy.sh` | Full deployment pipeline (build → certs → deploy → register → verify) |
| `scripts/deploy-all.sh` | Legacy TLS deployment script |
| `scripts/deploy-agent.sh` | Agent-only redeployment |
| `scripts/generate-certs.go` | TLS cert generation for nodes |
| `docs/` | Internal TODOs, naming research, cost projections |

## Infrastructure

Three nodes, all active:
- **vpn-us-west** (Oregon) — also runs the API server
- **vpn-ap-sgp** (Singapore)
- **vpn-eu-fin** (Helsinki)

See memory file `project_vpn_infra.md` for IPs and details. Never hardcode IPs in tracked files.

## Deployment

```bash
# Deploy to all nodes (build + certs + deploy + register + verify)
./scripts/deploy.sh

# Deploy to a single node
./scripts/deploy.sh vpn-eu-fin

# Terraform (careful — plan first, use -target for new nodes)
cd terraform && terraform plan
```

CRITICAL: Terraform will try to recreate existing nodes if `user_data` changed. Always use `-target` for new nodes to avoid destroying running infrastructure.

## Agent mode

All SaaS nodes run the agent in **managed mode** (`-mode managed`). The agent:
- Listens for peer add/remove from the API
- Reports bandwidth stats to the API every 60s
- Serves security status on GET /security

## API auth

- Admin endpoints: Bearer token (constant-time compare)
- Node bandwidth reporting: per-node token stored in `node_tokens` table
- Onboarding pages: token-based, 7-day expiry, single-use

## Database schema

Tables: `nodes`, `users`, `node_tokens`, `ip_counter`, `onboarding_tokens`, `network_rules`

No multi-tenancy yet. Each user is a VPN peer assigned to a node. Future SaaS work: add `tenant_id` for customer isolation, Stripe billing, web dashboard.

## Future SaaS work (Phase 2)

- [ ] Multi-tenant DB schema (tenant_id on users, nodes, tokens)
- [ ] Provisioning service (Hetzner API → cloud-init → register)
- [ ] Web dashboard (customer-facing peer management)
- [ ] Stripe billing (per-node subscriptions)
- [ ] Customer onboarding flow

## When editing SaaS code

- Never commit secrets or IPs. Use `.env` and `terraform.tfvars` (both gitignored).
- Source `.env` before running API commands: `source .env`
- The API URL and admin token come from env vars, not flags in production.
