# MyRelay (OSS)

Open-source, self-hosted WireGuard VPN toolkit (MIT). See `CLAUDE-oss.md` for full details.

The SaaS product (proprietary) lives in a separate repo: `github.com/PositiveControl/myrelay-cloud` (locally at `../myrelay-cloud`). The SaaS repo depends on this one for shared packages.

## Brand

- Name: **MyRelay**
- Domains: myrelay.to (primary), myrelayto.com (redirect)
- GitHub: github.com/PositiveControl/myrelay
- Go module: `github.com/PositiveControl/myrelay`

## Architecture

```
cmd/agent/           Agent (standalone + managed modes)
cmd/ctl/             CLI (local peer mgmt + generic API client)
cmd/tui/             TUI dashboard
internal/config/     Local peer config file
pkg/wireguard/       Key gen, peer sync, split tunneling
pkg/bandwidth/       Per-peer traffic monitoring
pkg/validate/        Input validation
pkg/models/          Data models
pkg/security/        Node security auditing
pkg/tlsutil/         TLS cert generation
pkg/httputil/        HTTP response helpers
examples/            Single-node Terraform example
scripts/setup-node.sh  Cloud-init bootstrap
```

## Roles

- **Admin** — runs a single node, manages peers directly via `vpnctl peer`.
- In SaaS context: the agent runs in managed mode and peers are managed by the user (customer) inside their isolated pod. See myrelay-cloud docs.

## Key Rules

- Never commit secrets, IPs, tokens, or personal info to tracked files.
- `.env`, `certs/`, `*.tfstate`, `terraform.tfvars` are gitignored.
- Shared packages (`pkg/`) are imported by both this repo and myrelay-cloud. Changes here affect both.
- The CLI includes a generic `vpnctl api` subcommand for calling any SaaS API endpoint without hardcoding SaaS-specific commands.

## Build

```bash
make all          # Build everything
make test         # Run tests with -race
make lint         # go vet + staticcheck
```
