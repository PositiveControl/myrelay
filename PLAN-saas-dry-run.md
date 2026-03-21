# SaaS Dry Run Plan

## Goal
End-to-end test of the SaaS flow: wipe DB, keep API on Oregon, re-register nodes, create first customer, deploy pod, onboard, test connectivity.

## Status: PAUSED
Paused to prioritize architectural changes (dedicated-node model). Resume when ready.

## Architecture Decision (2026-03-21)
Abandoning shared-node model (many users per node) in favor of **dedicated-node model**:
- 1 node per customer, single region, unlimited peers
- Premium pricing: $15+/mo
- Option to migrate regions or add regions at higher price
- Requires dynamic provisioning (provider-agnostic) — see beads issues myrelay-hem, myrelay-roe

The dry run below still uses the current shared-node architecture. Once the dedicated-node model is implemented, the dry run will need to be updated to reflect the new flow (signup -> provision dedicated server -> deploy agent -> onboard).

## Completed
- [x] Explored both repos (myrelay OSS + myrelay-cloud)
- [x] Copied .env from myrelay/ to myrelay-cloud/
- [x] Symlinked certs/ from myrelay/ to myrelay-cloud/
- [x] Verified API connectivity (https://5.78.83.247:8080)
- [x] Inventoried existing DB: 6 users, 3 nodes (vpn-us-west, vpn-ap-sgp, vpn-eu-fin)
- [x] Fixed port allocation bug in myrelay-cloud (listen_port column in user_subscriptions, NextListenPort DB method) — NOT YET DEPLOYED
- [x] Created beads issues for dedicated-node architecture and dynamic provisioning

## Port Allocation Fix (code done, not deployed)
Changed files in myrelay-cloud:
- `internal/db/db.go` — added listen_port column, migration, NextListenPort(), updated SubscribeUser() signature and all queries
- `internal/api/handlers/users.go` — uses NextListenPort() in Create() and SubscribeNodes()
- `internal/api/handlers/nodes.go` — uses NextListenPort() in Subscribe()

Build passes (`make all`, `make test`, `make lint`).

## Remaining Steps (when resumed)
1. Wipe DB on vpn-us-west: stop API, backup /var/lib/myrelay/vpn.db, delete, restart
2. Deploy updated API + agent binaries to all nodes (./scripts/deploy.sh)
   - This also re-registers nodes with the API
3. Create customer: POST /api/users with email=twenty4play@gmail.com, plan=premium, public_key=(generate client-side)
4. Generate onboarding token: POST /api/users/{id}/regen-config
5. Download config: GET /onboard/{token}/config
6. Import into WireGuard, test connectivity
7. Optionally subscribe to additional nodes

## Infrastructure Reference
- API server: vpn-us-west (5.78.83.247:8080)
- Nodes: vpn-us-west (hil), vpn-eu-fin (89.167.112.155, hel1), vpn-ap-sgp (5.223.70.143, sin)
- SSH user: deploy
- DB path on server: /var/lib/myrelay/vpn.db
- .env and certs are in myrelay/, symlinked/copied to myrelay-cloud/
