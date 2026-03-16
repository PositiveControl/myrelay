# Security Audit Report — VPN Service

**Date:** 2026-03-15
**Scope:** Application code, infrastructure, secrets management, deployment, physical security
**Status:** Complete (builder interview incorporated)

---

## Executive Summary

This audit examined the full stack of a ~100-user WireGuard VPN service: Go application code (API, agent, TUI, CLI), Terraform infrastructure, deployment scripts, secrets hygiene, and git history. The service runs on Hetzner Cloud with nodes in Oregon and Singapore, with a control plane API co-located on the Oregon node.

**Total findings: 53** across 4 audit domains.

| Severity | Count | Key Theme |
|----------|-------|-----------|
| CRITICAL | 8 | Private keys exposed via API, all traffic over plaintext HTTP, no input validation on WireGuard commands, unauthenticated agent mode, no cloud firewall |
| HIGH | 11 | Tokens logged/stored in plaintext, no TLS anywhere, root SSH with no host verification, no server hardening, onboarding tokens reusable |
| MEDIUM | 15 | No rate limiting, no CORS, timing attacks, bandwidth bypass, race conditions, subnet conflicts |
| LOW | 8 | No monitoring, no graceful shutdown, no request IDs |
| INFO | 6 | Positive findings and minor issues |

**The three most urgent issues:**
1. Every user's WireGuard private key is stored in the database and returned in every API response
2. All communication (API, agent, admin) uses plaintext HTTP — tokens travel in the clear
3. Production credentials (admin token, agent tokens) are stored in plaintext in Claude memory files on the developer machine

---

## CRITICAL Findings

### C1. Private keys stored in database and exposed via every API response
- **Severity:** CRITICAL
- **Files:** `internal/models/user.go:24`, `internal/db/db.go:164-165`, `internal/api/handlers/users.go:150,163,178`
- **Description:** The `User` struct has `PrivateKey string json:"private_key"` with no `json:"-"` tag. The private key is stored in SQLite in plaintext and returned in **every** API response that serializes a User: Create, List, Get. Calling `GET /api/users` dumps every user's WireGuard private key. A single compromised admin token leaks every user's VPN identity.
- **Fix:** Add `json:"-"` to PrivateKey. Encrypt at rest. Only include in one-time config download. Exclude from ListUsers SELECT query.

### C2. Server-side WireGuard key generation — server knows all user secrets
- **Severity:** CRITICAL
- **Files:** `internal/api/handlers/users.go:68-74`
- **Description:** The server generates WireGuard key pairs for users, meaning the control plane has full access to every user's private key. If the server or database is compromised, all user VPN traffic can be decrypted/impersonated.
- **Fix:** Have clients generate their own key pairs. Accept only public keys via the API. If server-side generation is needed for onboarding UX, delete the private key from the database after first download.

### C3. API server uses plaintext HTTP
- **Severity:** CRITICAL
- **Files:** `internal/api/server.go:64,75`, `cmd/api/main.go:13`
- **Description:** `ListenAndServe()` serves all endpoints (admin tokens, private keys, client configs) over unencrypted HTTP. Bearer tokens sent in cleartext on the wire.
- **Fix:** Use `ListenAndServeTLS()` or place behind a TLS-terminating reverse proxy. Refuse to start without TLS unless `--insecure` flag is passed.

### C4. Agent communication over plaintext HTTP
- **Severity:** CRITICAL
- **Files:** `internal/agent/client.go:15`, `cmd/agent/main.go:22,49`, `internal/api/handlers/nodes.go:122`
- **Description:** Agent URLs are `http://` only. Agent server uses `ListenAndServe`. Bearer tokens for both the agent API and control plane API are transmitted in cleartext HTTP Authorization headers.
- **Fix:** Use HTTPS with mTLS between agent and control plane.

### C5. Command injection risk via unsanitized WireGuard inputs
- **Severity:** CRITICAL
- **Files:** `internal/wireguard/wireguard.go:192-204`, `cmd/agent/main.go:125-148`
- **Description:** `SyncPeers()` passes user-supplied `publicKey` and `allowedIPs` directly to `exec.Command("wg", "set", ...)`. Zero input validation — public keys and AllowedIPs accepted with only empty-string checks. While `exec.Command` doesn't invoke a shell, malformed values cause undefined behavior in `wg`.
- **Fix:** Validate public keys (exactly 44 chars, valid base64, decodes to 32 bytes). Validate AllowedIPs with `net.ParseCIDR`. Validate interface names (alphanumeric, max 15 chars).

### C6. Authentication bypass when agent token is empty
- **Severity:** CRITICAL
- **Files:** `cmd/agent/main.go:88-101`
- **Description:** The `requireToken` middleware skips authentication entirely if `token == ""`. If the agent starts without `--token` or `AGENT_TOKEN` (defaults to `""`), all peer management endpoints are completely unauthenticated.
- **Fix:** Refuse to start the agent if no token is configured. Never allow unauthenticated access to peer management.

### C7. Production credentials in Claude memory files
- **Severity:** CRITICAL
- **File:** `~/.claude/projects/-Users-m7s-dev-vpn/memory/project_vpn_infra.md`
- **Description:** Contains in plaintext: admin token, both agent tokens, server public keys, server IPs, user email. Files persist on disk, readable by any process running as this user. Backup/sync tools could propagate them.
- **Fix:** Remove credentials from memory files immediately. Rotate all exposed tokens.

### C8. No Hetzner Cloud firewall configured
- **Severity:** CRITICAL
- **Files:** `terraform/nodes.tf`, `terraform/terraform.tfstate`
- **Description:** `"firewall_ids": []` — no cloud firewall attached to any server. Only host-level UFW via cloud-init. If cloud-init fails or UFW is disabled, nodes are completely exposed.
- **Fix:** Add `hcloud_firewall` resource in Terraform mirroring UFW rules. Defense in depth.

---

## HIGH Findings

### H1. WireGuard config template injection
- **Severity:** HIGH
- **Files:** `configs/wg0.conf.tmpl:1-14`, `internal/wireguard/wireguard.go:62-84`
- **Description:** Go `text/template` renders `{{ .PublicKey }}`, `{{ .AllowedIPs }}`, `{{ .Email }}`, `{{ .PublicInterface }}` without sanitization. The `PostUp`/`PostDown` lines execute iptables via shell — `{{ .PublicInterface }}` is interpolated into shell commands. A malicious value could inject arbitrary WireGuard directives or shell commands.
- **Fix:** Validate all template inputs strictly. Strip newlines from all fields.

### H2. Agent runs as root with no privilege separation
- **Severity:** HIGH
- **Files:** `internal/wireguard/wireguard.go:177-205`, `cmd/agent/main.go`
- **Description:** Agent calls `wg-quick`, `wg set`, `wg show` — requires root. The entire process including the HTTP server runs as root. Compromise of HTTP handler = root access to the node.
- **Fix:** Use Linux capabilities (CAP_NET_ADMIN). Drop privileges after setup. Run HTTP server in separate unprivileged process.

### H3. Admin token logged to stdout in plaintext
- **Severity:** HIGH
- **File:** `cmd/api/main.go:27`
- **Description:** Auto-generated admin token is logged via `log.Printf`. Visible in systemd journal, log aggregators, process output.
- **Fix:** Write to a secure file with 0600 permissions, or print once to stderr.

### H4. No request body size limit
- **Severity:** HIGH
- **Files:** `internal/api/handlers/users.go:42`, `internal/api/handlers/nodes.go:90,152`
- **Description:** `json.NewDecoder(r.Body).Decode()` with no size limit. Multi-gigabyte request body → OOM.
- **Fix:** Wrap with `http.MaxBytesReader(w, r.Body, 1<<20)`.

### H5. Onboarding tokens not invalidated after use
- **Severity:** HIGH
- **File:** `internal/api/onboard.go:53,161-180`
- **Description:** `MarkOnboardingTokenUsed` is called but `Used` flag is never checked in `validateOnboardingToken`. Token remains valid for 7 days regardless of use count. Anyone with the URL can download private key and config indefinitely.
- **Fix:** Check `tok.Used` in validation. Limit to 3 downloads max. Shorten expiry window.

### H6. Terraform state stored locally
- **Severity:** HIGH
- **Files:** `terraform/main.tf:11-16`, `terraform/terraform.tfstate`
- **Description:** Remote backend is commented out. State file on developer laptop contains server IPs, SSH key IDs, email. No encryption, no locking, no access control.
- **Fix:** Enable S3 backend with `encrypt = true` and DynamoDB lock table.

### H7. SSH deployed as root with StrictHostKeyChecking disabled
- **Severity:** HIGH
- **File:** `scripts/deploy-agent.sh:10-11`
- **Description:** `SSH_USER="root"` and `SSH_OPTS="-o StrictHostKeyChecking=no"`. MITM attacks possible during deployment.
- **Fix:** Use a dedicated deploy user. Pre-populate known_hosts with server fingerprints from Terraform output.

### H8. Server delete protection disabled
- **Severity:** HIGH
- **File:** `terraform/terraform.tfstate`
- **Description:** `"delete_protection": false` and `"rebuild_protection": false` on all servers. Accidental `terraform destroy` wipes everything.
- **Fix:** Add `delete_protection = true`, `rebuild_protection = true`, and `lifecycle { prevent_destroy = true }`.

### H9. No server hardening in setup script
- **Severity:** HIGH
- **File:** `scripts/setup-node.sh`
- **Description:** Missing: fail2ban, unattended-upgrades, SSH hardening (password auth disable, root login restriction), log forwarding, kernel hardening beyond IP forwarding.
- **Fix:** Install fail2ban and unattended-upgrades. Harden sshd_config. Enable audit logging.

### H10. IP address space exhaustion — no bounds check
- **Severity:** HIGH
- **Files:** `internal/db/db.go:376-394`, `internal/api/handlers/users.go:94`
- **Description:** `NextIP()` returns ever-incrementing counter, formatted as `10.0.0.%d`. No check for >254. Produces invalid configs.
- **Fix:** Validate `nextIP <= 254`. Implement proper IP allocation spanning multiple /24 subnets.

### H11. Backups disabled on all servers
- **Severity:** HIGH
- **File:** `terraform/terraform.tfstate`
- **Description:** `"backups": false` on all instances. WireGuard keys and peer configs lost on disk failure.
- **Fix:** Enable Hetzner backups or implement external backup for `/etc/wireguard/` and the SQLite database.

---

## MEDIUM Findings

### M1. No config file permission control
- **Files:** `configs/wg0.conf.tmpl`, `internal/wireguard/wireguard.go:177`
- **Description:** No code sets file permissions on generated WireGuard configs. Default permissions may allow any local user to read server private keys.
- **Fix:** Use `os.OpenFile` with `0600` mode.

### M2. Race condition — no file locking on config operations
- **File:** `internal/wireguard/wireguard.go:177-205`
- **Description:** No mutex serializing `wg-quick down/up` and `wg set` calls. Concurrent requests cause inconsistent WireGuard state.
- **Fix:** Add a mutex in the agent server for all WireGuard operations.

### M3. Private key exposed in TUI user model
- **File:** `cmd/tui/main.go:51`
- **Description:** TUI User struct includes `PrivateKey` — API returns private keys to admin dashboard. Held in memory even if not displayed.
- **Fix:** Never return private keys from API. Remove field from TUI model.

### M4. Agent token exposed via CLI flags
- **File:** `cmd/agent/main.go:25`
- **Description:** `--token` flag visible via `/proc/<pid>/cmdline` or `ps aux`.
- **Fix:** Only accept token via environment variable or file path.

### M5. Bandwidth monitor counter manipulation
- **File:** `internal/bandwidth/monitor.go:123-129`
- **Description:** WireGuard interface restart resets tracked bandwidth to zero. Attacker can bypass quotas.
- **Fix:** Persist cumulative bandwidth to database. Add previous total on counter reset.

### M6. Error messages leak internal details
- **Files:** `cmd/agent/main.go:139,165,179`, `internal/api/handlers/users.go:100`, `internal/api/handlers/nodes.go:114`
- **Description:** Raw error messages (including command output, file paths, database errors) returned to clients. Also uses string interpolation in JSON — `"` in errors produces malformed JSON.
- **Fix:** Return generic errors to clients. Log details server-side. Use `json.Marshal`.

### M7. Node ID controlled by client
- **File:** `internal/api/handlers/nodes.go:88-129`
- **Description:** Node registration accepts `id` from JSON body. Allows overwriting existing nodes.
- **Fix:** Generate node IDs server-side.

### M8. No CORS headers configured
- **File:** `internal/api/server.go:28-50`
- **Description:** No explicit CORS policy. Currently safe by default but fragile.
- **Fix:** Add explicit restrictive CORS middleware.

### M9. Onboarding token enumeration via timing
- **File:** `internal/api/onboard.go:161-180`
- **Description:** Response time differs between "not found" and "found but expired".
- **Fix:** Add constant-time response delays.

### M10. SSH port open to all sources
- **File:** `scripts/setup-node.sh:50`
- **Description:** `ufw allow 22/tcp` — SSH open to the entire internet.
- **Fix:** Restrict to management IPs or use SSH over WireGuard.

### M11. Agent API port open to all sources
- **File:** `scripts/setup-node.sh:52`
- **Description:** `ufw allow 8081/tcp` — agent API open to the internet.
- **Fix:** `ufw allow from <API_SERVER_IP> to any port 8081 proto tcp`.

### M12. SQLite database file has no explicit permissions
- **File:** `internal/db/db.go:21`
- **Description:** Database created with default umask. Contains private keys and tokens.
- **Fix:** Set permissions to 0600 after opening.

### M13. Node tokens stored in plaintext in database
- **File:** `internal/db/db.go:250-256`
- **Description:** Node auth tokens stored as plaintext. Database compromise = all tokens usable.
- **Fix:** Store SHA-256 hashed tokens. Compare by hashing incoming token.

### M14. WireGuard subnet conflicts across nodes
- **File:** `scripts/setup-node.sh:34`
- **Description:** Every node uses `10.0.0.1/24` — identical subnets prevent inter-node routing.
- **Fix:** Assign unique subnets per node (10.0.1.0/24, 10.0.2.0/24, etc.).

### M15. Agent environment file is optional
- **File:** `scripts/setup-node.sh:70`
- **Description:** `EnvironmentFile=-/opt/vpn-agent/.env` — the `-` prefix means service starts even without the file, potentially in unauthenticated mode.
- **Fix:** Remove the `-` prefix.

---

## LOW Findings

### L1. No rate limiting on any endpoint
- **Files:** `internal/api/server.go:79-110`, `cmd/agent/main.go:85-118`
- **Fix:** Add rate limiting middleware, especially on auth and public endpoints.

### L2. Client config uses /24 instead of /32
- **Files:** `internal/api/onboard.go:129-131`, `internal/api/handlers/users.go:364-366`
- **Fix:** Use /32 for point-to-point VPN (WireGuard best practice).

### L3. No graceful shutdown handling
- **File:** `cmd/api/main.go:40-42`
- **Fix:** Implement signal handling with `server.Shutdown(ctx)`.

### L4. Concurrent map access on agent client
- **File:** `internal/agent/client.go:30-33`
- **Fix:** Add `sync.RWMutex` to `Client` struct.

### L5. CLI tool uses HTTP by default
- **File:** `cmd/ctl/main.go:21`
- **Fix:** Default to HTTPS or warn on non-localhost HTTP.

### L6. Unbounded bandwidth data from nodes
- **File:** `internal/api/handlers/nodes.go:138-167`
- **Fix:** Validate peer keys correspond to actual users. Limit entries per report.

### L7. No infrastructure monitoring or alerting
- **Fix:** Deploy Prometheus node_exporter, set up alerting for SSH logins and WireGuard state.

### L8. No `.claude/` entry in `.gitignore`
- **Description:** `.claude/` was removed from `.gitignore` in commit `4d1317e`. Future `git add .` could commit memory files containing credentials.
- **Fix:** Add `.claude/projects/*/memory/` to `.gitignore`.

---

## INFO / Positive Findings

- `.gitignore` properly excludes `.env`, `*.tfstate`, `terraform.tfvars`, `*.key`, `*.pem`, binaries
- No secret files were ever committed to git history (confirmed via full history scan)
- No compiled binaries tracked in git
- WireGuard key generation in setup script uses proper `umask 077` and `chmod 600`
- Token comparison uses `subtle.ConstantTimeCompare` (constant-time)
- Auto-generated admin token when none configured (good default)
- Git remote uses SSH, not HTTPS with embedded credentials
- Health endpoint unauthenticated by design (expected for load balancers)

---

## Builder Interview Responses & Additional Findings

### Access & Authentication
1. **SSH**: Key-based authentication. **Root login is enabled.** Single user (builder). No other SSH users.
2. **Hetzner 2FA**: Enabled. Sole account access.
3. **Admin token**: Generated today (2026-03-15) during initial setup. Never rotated. Same token in memory file.

### Network & Physical
4. **API exposure**: Port 8080 is **exposed to the public internet** with no IP restrictions. → **Escalates C3 severity.** The admin API (with full private key access) is reachable by anyone on the internet over plaintext HTTP.
5. **DNS/TLS**: No domain name. Raw IPs only. No TLS plans yet.
6. **Dev machine**: Home network, password-protected, FileVault encrypted, not shared. → **Acceptable for current stage.** Physical security is adequate.

### Operations
7. **Backups**: **None.** No SQLite backups, no Terraform state backups. → **NEW FINDING (HIGH):** A disk failure on vpn-us-west destroys the user database, all WireGuard private keys, and all peer configurations with no recovery path.
8. **Monitoring**: TUI only. No automated alerting. → **NEW FINDING (MEDIUM):** Node compromise would go undetected until users report issues.
9. **Incident response**: "Shut down the node." No formal plan. → **Acceptable for beta** given single-operator model, but needs formalization before paying customers.
10. **User onboarding**: No identity verification yet. → **Risk deferred** — friends & family beta means implicit trust. Must be addressed before public launch.

### Supply Chain & Development
11. **Other developers/CI**: None. Solo operator. → **Reduces attack surface** but creates single point of failure.
12. **Dependency updates**: Never. → **NEW FINDING (HIGH):** Go dependencies have never been audited or updated. Known vulnerabilities in transitive dependencies may exist. Run `govulncheck` immediately.
13. **Deployment**: Manual SSH. → **Consistent with H7** (root SSH, no host key verification).

### Regulatory / Legal
14. **Logging policy**: Builder wants **zero logging** beyond health/debug metrics. → **Good privacy stance** but needs formal documentation. Consider: what happens when law enforcement asks for logs you don't have?
15. **Legal awareness**: Unknown. → **NEW FINDING (MEDIUM):** US VPN operators may have obligations under CALEA (Communications Assistance for Law Enforcement Act). While small-scale services are generally not classified as "telecommunications carriers," this is a gray area that has been tested in court. A basic legal consultation (~$500) before accepting payment would clarify obligations and protect the builder personally.

### Interview-Derived Findings Summary

| ID | Severity | Finding |
|----|----------|---------|
| I-H1 | HIGH | No backups of any kind — total data loss on disk failure |
| I-H2 | HIGH | Go dependencies never audited — **govulncheck found 18 active vulnerabilities** (see appendix) |
| I-M1 | MEDIUM | No automated monitoring — compromise detection depends on user reports |
| I-M2 | MEDIUM | Unknown CALEA/legal obligations — get a basic legal consultation |
| I-L1 | LOW | No formal incident response plan (acceptable for beta) |
| I-L2 | LOW | No onboarding identity verification (acceptable for F&F beta) |
| I-INFO | INFO | Physical security adequate (encrypted disk, password, sole access, home network) |
| I-INFO | INFO | Sole operator reduces collaboration attack surface |

---

## Updated Findings Summary

| Severity | Code Audit | Infra Audit | Secrets Audit | Agent/WG Audit | Interview | **Total** |
|----------|-----------|-------------|---------------|----------------|-----------|-----------|
| CRITICAL | 4 | 4 | 2 | 2 | 0 | **8** (deduplicated) |
| HIGH | 6 | 5 | 1 | 4 | 2 | **13** |
| MEDIUM | 7 | 6 | 2 | 6 | 2 | **17** |
| LOW | 4 | 2 | 0 | 4 | 2 | **10** |
| INFO | 3 | 3 | 5 | 2 | 2 | **8** |
| **Total** | | | | | | **56** |

---

## Recommended Remediation Priority

### Immediate (do today)
1. **Rotate all tokens** — admin token and both agent tokens are exposed in memory files
2. **Remove credentials from Claude memory files**
3. **Add `.claude/projects/*/memory/` to `.gitignore`**
4. **Run `govulncheck`** — dependencies have never been checked for known vulnerabilities

### This week
5. **Add TLS** to API and agent communication (Let's Encrypt + reverse proxy or in-app TLS)
6. **Get a domain name** — required for Let's Encrypt, also improves operational security vs raw IPs
7. **Fix private key exposure** — add `json:"-"`, exclude from list queries, delete after config download
8. **Add input validation** for WireGuard public keys, AllowedIPs, interface names
9. **Require agent token** — refuse to start without one
10. **Add Hetzner Cloud firewall** in Terraform
11. **Restrict agent API port** to control plane IP only
12. **Invalidate onboarding tokens after use**
13. **Enable Hetzner server backups** — $1.19/mo per server, protects against total data loss
14. **Set up automated SQLite backups** — daily `sqlite3 vpn.db ".backup /opt/backups/vpn-$(date +%Y%m%d).db"`

### This month
15. Move to client-side key generation
16. Enable remote Terraform backend with encryption
17. Server hardening (fail2ban, unattended-upgrades, SSH hardening, disable root login)
18. Add request body size limits
19. Enable server delete/rebuild protection
20. Add rate limiting
21. Implement privilege separation for agent
22. Fix IP address space exhaustion
23. Add basic monitoring (node_exporter + simple uptime check)
24. Update Go dependencies and establish a monthly update cadence

### Before accepting paying customers
25. **Legal consultation** on CALEA and US VPN operation requirements (~$500)
26. Formal incident response plan
27. Privacy policy and zero-logging policy documentation
28. Penetration test by external party
29. Stripe integration security review
30. User-facing security documentation
31. Onboarding identity verification

---

## Appendix A: govulncheck Results (2026-03-15)

**Go version:** go1.24.2 (severely outdated)
**Active vulnerabilities affecting your code:** 18
**Additional vulnerabilities in imported packages:** 4
**Vulnerabilities in required modules (not called):** 3

### Most critical (exploitable in your code paths):

| ID | Package | Impact | Fixed In | Affected Code |
|----|---------|--------|----------|---------------|
| GO-2026-4603 | html/template | URL injection in meta content | go1.25.8 | `api/onboard.go:31` — onboarding page template |
| GO-2026-4601 | net/url | IPv6 host parsing bypass | go1.25.8 | `agent/client.go`, `api/server.go` |
| GO-2026-4341 | net/url | Memory exhaustion via query params | go1.24.12 | `db/db.go:21` — SQLite connection |
| GO-2026-4340 | crypto/tls | Handshake at wrong encryption level | go1.24.12 | `api/server.go`, `agent/client.go` |
| GO-2025-3956 | os/exec | Unexpected LookPath results | go1.24.6 | `wireguard/wireguard.go:193` — `wg` command execution |
| GO-2025-3849 | database/sql | Incorrect Rows.Scan results | go1.24.6 | `db/db.go:384,350` — IP allocation, network rules |
| GO-2025-3751 | net/http | Auth headers leaked on redirect | go1.24.4 | `agent/client.go:88` — agent token leakage on redirect |
| GO-2025-4012 | net/http | Cookie parsing memory exhaustion | go1.24.8 | `agent/client.go` |

**Immediate action:** Update Go to at least 1.24.13 (latest patch) or 1.25.8, then rebuild and redeploy all binaries.
