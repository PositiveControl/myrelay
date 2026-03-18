# MyRelay OSS

The open-source, self-hosted WireGuard VPN toolkit. Everything a self-hoster needs to run a private VPN on a single server — no account system, no cloud dependency.

## What ships in OSS

| Path | Purpose |
|------|---------|
| `cmd/agent/` | Agent binary — standalone mode watches `peers.json`, managed mode for SaaS |
| `cmd/ctl/` | CLI — local peer commands (`peer add/remove/list`, `config show`, `qr`) + remote API client |
| `cmd/tui/` | TUI dashboard — real-time node/peer monitoring |
| `internal/config/` | JSON peer config file: load, save, add/remove peers, IP allocation |
| `internal/wireguard/` | Key generation, peer sync (`wg set`), split tunneling, server key reading |
| `internal/bandwidth/` | Per-peer bandwidth monitoring via `wg show transfer` |
| `internal/validate/` | Input validation (WireGuard keys, CIDR, interface names, IPs) |
| `internal/models/` | User and Node data models |
| `internal/security/` | Node security status collection (fail2ban, SSH, UFW, TLS) |
| `internal/tlsutil/` | TLS CA and server cert generation |
| `internal/httputil/` | HTTP JSON response helpers |
| `examples/hetzner/` | Single-node Terraform example with cloud-init |
| `scripts/setup-node.sh` | Cloud-init node bootstrap script |
| `LICENSE` | MIT |
| `README.md` | Self-hosting quickstart and docs |

## What does NOT ship in OSS

- `cmd/api/` — Multi-user control plane API
- `internal/api/` — API handlers, auth middleware, onboarding pages
- `internal/agent/client.go` — API→node communication client
- `internal/db/` — SQLite database layer
- `terraform/` — Multi-node production infrastructure
- `scripts/deploy.sh` — Cluster deployment pipeline
- `docs/` — Internal docs and TODOs

## OSS branch

Work happens on `feat/oss-standalone`. Key changes from main:

- Agent defaults to `-mode standalone` (watches peers.json)
- CLI has local `peer` commands that don't need an API
- Client-side key generation (private keys never stored server-side)
- Module path: `github.com/PositiveControl/myrelay`

## Self-hoster flow

```
vpnctl peer add alice  →  writes /etc/vpn/peers.json
                       →  agent detects change
                       →  wg set peer <pubkey> allowed-ips 10.0.0.2/32
```

No API, no database, no remote calls.

## Testing

```bash
go test -race ./internal/config/     # Config package (10 tests)
go test -race ./internal/wireguard/  # WireGuard split tunneling tests
```

## When editing shared packages

`wireguard`, `bandwidth`, `validate`, `models`, `security`, `tlsutil`, `httputil` are used by both OSS and SaaS. Changes here should work for both standalone and managed modes.
