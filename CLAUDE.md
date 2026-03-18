# MyRelay

WireGuard VPN toolkit split into two products under one brand:

1. **OSS** (MIT) — Self-hosted single-node VPN. See `CLAUDE-oss.md`.
2. **SaaS** (proprietary) — Managed multi-node service. See `CLAUDE-saas.md`.

## Brand

- Name: **MyRelay**
- Domains: myrelay.to (primary), myrelayto.com (redirect)
- GitHub: github.com/PositiveControl/myrelay
- Go module: `github.com/PositiveControl/myrelay`

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    OSS (MIT)                         │
│                                                     │
│  cmd/agent/      Agent (standalone + managed modes) │
│  cmd/ctl/        CLI (local peer mgmt + API client) │
│  cmd/tui/        TUI dashboard                      │
│  internal/config/     Local peer config file         │
│  internal/wireguard/  Key gen, peer sync, split tun  │
│  internal/bandwidth/  Per-peer traffic monitoring    │
│  internal/validate/   Input validation               │
│  internal/models/     Data models                    │
│  internal/security/   Node security auditing         │
│  internal/tlsutil/    TLS cert generation            │
│  internal/httputil/   HTTP response helpers          │
│  examples/            Single-node Terraform example  │
│  scripts/setup-node.sh  Cloud-init bootstrap         │
├─────────────────────────────────────────────────────┤
│                    SaaS (proprietary)                │
│                                                     │
│  cmd/api/             Control plane API server       │
│  internal/api/        Handlers, auth, onboarding     │
│  internal/agent/      API→node client (managed mode) │
│  internal/db/         SQLite multi-user database     │
│  terraform/           Multi-node Hetzner infra       │
│  scripts/deploy.sh    Cluster deployment pipeline    │
│  scripts/deploy-all.sh  Legacy deploy (TLS)          │
│  scripts/deploy-agent.sh  Agent-only deploy          │
│  scripts/generate-certs.go  TLS cert generation      │
│  docs/                Internal docs and TODOs        │
└─────────────────────────────────────────────────────┘
```

## Key Rules

- Never commit secrets, IPs, tokens, or personal info to tracked files.
- `.env`, `certs/`, `*.tfstate`, `terraform.tfvars` are gitignored.
- The OSS branch is `feat/oss-standalone`. Main is the SaaS/managed codebase.
- When editing shared packages (wireguard, bandwidth, models, validate), changes affect both products.

## Build

```bash
make all          # Build everything
make test         # Run tests with -race
make lint         # go vet + staticcheck
```
