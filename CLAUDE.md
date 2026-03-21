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
- In SaaS context: each customer gets a dedicated node running the agent in standalone mode. Customers manage their own peers. See myrelay-cloud docs.

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


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:b9766037 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
