# MyRelay Security

This document describes the security architecture and practices of the MyRelay VPN service.

## WireGuard

MyRelay uses [WireGuard](https://www.wireguard.com/), a modern VPN protocol that is:

- **Small attack surface** — ~4,000 lines of code in the Linux kernel module, vs. 100,000+ for OpenVPN/IPsec
- **Strong cryptography** — Curve25519 for key exchange, ChaCha20-Poly1305 for encryption, BLAKE2s for hashing
- **Forward secrecy** — session keys are rotated frequently and not derivable from long-term keys
- **Minimal state** — no connection state to attack when idle; silent to unauthenticated packets

## Key management

- **Client-side key generation.** Your WireGuard private key is generated on your device and never leaves it. The server only receives your public key.
- **Per-node server keys.** Each VPN node has its own WireGuard keypair generated at provisioning time.
- **Per-pod isolation.** Each customer gets a dedicated WireGuard interface with its own keypair on each subscribed node. Your pod is cryptographically separate from every other customer.

## Network isolation

Customer pods are isolated at the Linux kernel level:

- Each customer gets a dedicated WireGuard network interface (e.g., `wg-abc123`) per node
- Interfaces have separate subnets, keypairs, and firewall rules
- The control plane manages pod lifecycle but cannot see traffic inside pods
- Pod-scoped authentication tokens ensure customers can only manage their own peers

This is stronger than application-level isolation — a vulnerability in one customer's pod cannot affect another.

## Infrastructure security

### Encryption in transit
- All API and agent communication uses TLS with ECDSA certificates
- WireGuard traffic is encrypted end-to-end between your device and the VPN node
- The API server refuses to start without TLS unless explicitly overridden

### Server hardening
- SSH access restricted to key-based authentication, no password login
- Root login restricted to key-based only (`PermitRootLogin prohibit-password`)
- fail2ban protects against SSH brute force attacks
- Automatic security updates via `unattended-upgrades`
- Hetzner Cloud firewall + host-level UFW (defense in depth)
- Agent runs as a dedicated unprivileged user with only `CAP_NET_ADMIN` capability

### Authentication
- Admin API tokens are cryptographically generated (256-bit)
- Node tokens are stored as SHA-256 hashes in the database
- All token comparisons use constant-time operations to prevent timing attacks
- API endpoints enforce per-IP rate limiting

### Data at rest
- WireGuard configuration files have restrictive permissions (0600)
- SQLite database has restrictive permissions (0600)
- Private keys are never stored on the server (client-side generation)
- Daily encrypted backups of the API database

### Input validation
- All WireGuard public keys validated (44 chars, valid base64, decodes to 32 bytes)
- All CIDR addresses validated with `net.ParseCIDR`
- All interface names validated (alphanumeric, max 15 chars)
- Request body size limits (1MB) on all API endpoints
- Template inputs sanitized against WireGuard directive injection

## What we don't do

- We do not log, inspect, or store your VPN traffic
- We do not perform deep packet inspection
- We do not inject ads, trackers, or modify your traffic
- We do not share data with third parties
- We do not use analytics or telemetry in the VPN software

See our [Privacy Policy](privacy-policy.md) for full details.

## Reporting vulnerabilities

If you discover a security vulnerability, please report it responsibly. Contact the service administrator directly rather than opening a public issue.

## Open source

The core VPN software is open source under the MIT license at [github.com/PositiveControl/myrelay](https://github.com/PositiveControl/myrelay). You can audit the code yourself.
