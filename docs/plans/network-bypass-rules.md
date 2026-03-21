# Network Bypass Rules

**Branch:** `network-bypass-rules`
**Status:** Feature-complete implementation, not merged
**Date:** 2026-03-15
**Archived from:** stale worktree `.claude/worktrees/network-bypass-rules/`

## Overview

Selective VPN traffic routing where users define networks (CIDR) to exclude from the VPN tunnel. When a user has bypass rules, their WireGuard client config's `AllowedIPs` is computed as `0.0.0.0/0` minus all excluded networks, so only non-excluded traffic routes through the VPN.

## Data Model

```go
// internal/models/rule.go
type NetworkRule struct {
    ID      int64
    UserID  int64
    Name    string
    Network string  // CIDR notation, e.g. "192.168.1.0/24"
    Action  string  // currently only "bypass"
}
```

Database table: `network_rules` with foreign key to `users` (cascade delete).

## API Endpoints

```
GET    /api/users/{id}/rules          List bypass rules for a user
POST   /api/users/{id}/rules          Create a bypass rule
DELETE /api/users/{id}/rules/{ruleId}  Delete a rule
GET    /api/users/{id}/config         Generate WireGuard client config with rules applied
```

## Core Algorithm: CIDR Subtraction

`internal/wireguard/split.go` — `ComputeAllowedIPs(excludedCIDRs []string) (string, error)`

Algorithm:
1. Start with universe `0.0.0.0/0`
2. For each excluded CIDR, subtract from all current ranges via `subtractCIDR()`
3. `subtractCIDR()` recursively splits parent CIDR in half if it overlaps with the exclusion
4. Results sorted by IP then prefix length for determinism
5. Returns comma-separated CIDR string for WireGuard `AllowedIPs`

Helper: `splitCIDR(cidr)` splits a CIDR block into two equal halves by incrementing the prefix length by 1.

**Example:** Exclude `192.168.1.0/24` from `0.0.0.0/0` produces ranges covering everything except that /24.

### Test Coverage (`split_test.go`)
- No exclusions -> `"0.0.0.0/0"`
- Single exclusion -> correct complement
- Multiple exclusions -> correct coverage with no overlaps
- Invalid CIDR -> error
- Exclude everything -> empty string

## Config Generation Flow

```go
// internal/api/handlers/users.go (lines 300-366)
rules, _ := h.db.ListNetworkRules(userID)
var excludedCIDRs []string
for _, rule := range rules {
    if rule.Action == "bypass" {
        excludedCIDRs = append(excludedCIDRs, rule.Network)
    }
}
allowedIPs, _ := wireguard.ComputeAllowedIPs(excludedCIDRs)
// Generate WireGuard client config with computed AllowedIPs
```

## Database Methods (`internal/db/db.go`)

- `CreateNetworkRule(userID, name, network, action)` — insert rule
- `ListNetworkRules(userID)` — list all rules for a user
- `DeleteNetworkRule(ruleID, userID)` — delete by ID (scoped to user)

Schema includes `network_rules` table with columns: `id`, `user_id`, `name`, `network`, `action`, foreign key on `user_id` with cascade delete.

## Authentication

Two-tier auth in `internal/api/auth.go`:
- **Admin token** — 32-byte random hex, generated at startup if not provided
- **Per-node tokens** — 32-byte random, generated on node registration
- Both use constant-time comparison
- `RequireNodeOrAdmin()` middleware for provision and bandwidth endpoints

## Additional Infrastructure in This Branch

This branch also contained a full control plane implementation beyond just bypass rules:

- **User management** with automatic WireGuard key generation, plan tiers (Standard/Premium), bandwidth limits
- **Node management** with registration, sync, capacity tracking
- **Bandwidth monitoring** — agents poll WireGuard, report to control plane every 60s
- **Terraform provisioning** — Hetzner Cloud with cloud-init, multi-region via for-each
- **CLI** (`cmd/ctl/`) and **TUI** (`cmd/tui/`) admin tools
- **SQLite** with WAL mode, transactional IP allocation counter

## Design Decisions

1. **CIDR subtraction over routing tables** — computed at config generation time, no runtime overhead on nodes
2. **Only "bypass" action** — simple model, extensible to "allow-only" later
3. **Per-user rules** — rules scoped to individual users, cascade-deleted with user
4. **No ORM** — raw SQL for small binary size and full control
5. **WireGuard CLI tools** — uses `wg`/`wg-quick` binaries, not Go WireGuard library
6. **Config template rendering** — text/template for client config generation

## Not Addressed

- IPv6 support in CIDR arithmetic (only IPv4 tested)
- Rule conflict detection or optimization
- Per-rule enable/disable toggle
- Rule expiration or time-based rules
- User-facing web UI (CLI/TUI only)

## Key Files Reference

| File | Purpose |
|------|---------|
| `internal/wireguard/split.go` | CIDR subtraction algorithm |
| `internal/wireguard/split_test.go` | Algorithm tests |
| `internal/models/rule.go` | NetworkRule data model |
| `internal/api/handlers/users.go` | Rule CRUD + config generation endpoints |
| `internal/db/db.go` | Database schema + rule queries |
| `internal/api/auth.go` | Auth middleware |
| `cmd/agent/main.go` | Node agent with bandwidth monitoring |
