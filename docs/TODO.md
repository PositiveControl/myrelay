# TODO

## High Priority

- [ ] **Module rename**: Go module path is `github.com/m7s/vpn` but the repo is at `github.com/PositiveControl/vpn`. Rename module to `github.com/PositiveControl/vpn` and update all imports.
- [ ] Rotate admin token and agent tokens (exposed in memory file during audit)
- [ ] Request body size limits (`http.MaxBytesReader`) on all JSON decode endpoints
- [ ] Rate limiting middleware on API endpoints
- [ ] IP address space bounds check (NextIP > 254 produces invalid addresses)
- [ ] Enable Hetzner server backups (~$1.19/mo per server)
- [ ] Set up automated SQLite backups (daily cron)
- [ ] Restrict SSH in UFW to management IPs (currently open to 0.0.0.0/0)
- [ ] Apply Terraform firewall changes (`terraform apply` — firewall.tf + variables.tf)

## Medium Priority

- [ ] Move to client-side WireGuard key generation
- [ ] Enable remote Terraform backend with encryption
- [ ] Add request ID / client IP to API access logs
- [ ] Implement privilege separation for agent (CAP_NET_ADMIN instead of root)
- [ ] Fix subnet conflicts across nodes (all use 10.0.0.1/24)
- [ ] Remove optional `-` prefix from agent EnvironmentFile in setup-node.sh
- [ ] Add CORS headers to API
- [ ] Hash node tokens in database (store SHA-256, not plaintext)

## Low Priority

- [ ] Graceful shutdown handling for API server
- [ ] Client config should use /32 not /24 (WireGuard best practice)
- [ ] Unbounded bandwidth data per node — validate peer keys against actual users
- [ ] CLI default URL should warn when using HTTP for non-localhost

## Pre-Launch (Before Paying Customers)

- [ ] Legal consultation on CALEA / US VPN obligations (~$500)
- [ ] Formal incident response plan
- [ ] Privacy policy and zero-logging policy documentation
- [ ] External penetration test
- [ ] Stripe integration security review
- [ ] Onboarding identity verification
- [ ] User-facing security documentation
