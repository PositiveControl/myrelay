# Alpine RAM-Only Nodes

**Branch:** `feature/alpine-ram-only`
**Status:** Phase 1 (code) complete; Phases 2-4 (image creation, migration, deployment) not started
**Date:** 2026-03-15
**Archived from:** stale worktree `.claude/worktrees/alpine-ram-only/`

## Overview

RAM-only (diskless) VPN node infrastructure using Alpine Linux. All node data, keys, and logs live in tmpfs and are wiped on every reboot or power loss. Fresh WireGuard keypairs are generated on each boot via a provision-on-boot flow.

## Architecture

```
[Node powers on]
  -> BIOS loads kernel + initramfs from /boot on SSD (~50 MB)
  -> initramfs mounts tmpfs as root, unpacks Alpine + WireGuard + agent
  -> Agent starts with -provision flag
  -> Agent contacts API: POST /api/nodes/{id}/provision
     - Generates fresh WireGuard keypair
     - Sends public key to control plane
     - Receives current peer list
  -> WireGuard interface comes up in RAM with all peers
  -> Node is operational
```

All runtime state (configs, keys, logs, agent binary) lives in tmpfs. The SSD contains only `/boot`.

## Recommendation

**Option 1: Alpine diskless mode on Hetzner Cloud** was selected over:
- Option 2: Vultr custom ISO (+330-430% cost)
- Option 3: Bare-metal PXE (8-40x cost, future upgrade path)
- Option 4: Decentralized nodes (separate analysis)

Cost: zero additional cost vs current Ubuntu infrastructure (same CPX11/CPX12 instances).

## Key Code Changes

### Agent (`cmd/agent/main.go`)
- `-provision` flag / `PROVISION=1` env var enables RAM-only mode
- `provisionNode()` function: generates fresh keypair, POSTs to `/api/nodes/{id}/provision`, receives peer list, writes config to tmpfs, brings up WireGuard interface

### API Endpoint (`internal/api/handlers/nodes.go`)
- `POST /api/nodes/{id}/provision` — accepts `{"public_key": "..."}`, updates node's key in DB, returns node info + peer list
- Authenticated via `RequireNodeOrAdmin()` middleware (accepts per-node token or admin token)

### Database (`internal/db/db.go`)
- `UpdateNodePublicKey(id, publicKey)` — stores fresh key on each boot
- `ListNodePeers(nodeID)` — returns all users assigned to a node

### Scripts
- `scripts/setup-node-alpine.sh` — standalone Alpine bootstrap (apk install, OpenRC service, IP forwarding)
- `scripts/setup-node-ram-only.sh.tftpl` — Terraform template variant with variable injection (NODE_ID, AGENT_TOKEN, API_URL, PROVISION=1)
- `scripts/build-alpine-image.sh` — creates Hetzner snapshot: spins up temp Ubuntu, installs Alpine 3.21 diskless, takes snapshot, destroys temp server (not yet executed)
- `scripts/deploy-agent.sh` — enhanced to detect init system (systemd vs OpenRC)

### Terraform (`terraform/`)
- `var.node_configs` — per-node map with `node_id` and `agent_token` (sensitive); presence triggers RAM-only mode
- `var.api_url` — control plane URL for provisioning
- `var.image` — OS image selector (defaults ubuntu-24.04, can be Alpine snapshot ID)
- `locals.is_ram_only` — conditional: uses `templatefile()` for Alpine, falls back to `setup-node.sh` for Ubuntu
- Labels: `mode = "ram-only"` or `mode = "standard"`

## Threat Model

| Threat | Disk-based | Alpine RAM-only | Bare-metal PXE |
|--------|-----------|-----------------|----------------|
| Server seizure (off) | All data recoverable | Nothing recoverable | Nothing recoverable |
| Server seizure (on) | RAM + disk | RAM dump only | RAM dump only |
| Malicious host provider | Full access | Full hypervisor access | Physical access only |
| Remote compromise + reboot | Attacker persists | Attacker wiped | Attacker wiped |
| Boot image tampering | Possible | Possible (SSD) | Harder (signed PXE) |

**Limitations:** Hetzner hypervisor can inspect RAM; SSD boot partition is tamper-possible; no swap (RAM exhaustion = crash, unlikely for WireGuard workloads); 2 GB RAM sufficient (~200 MB OS + ~50 MB agent + ~1.7 GB headroom).

## Remaining Work

- [ ] Phase 2: Run `build-alpine-image.sh` to create Hetzner snapshot, test boot + SSH
- [ ] Phase 3: Build linux/amd64 agent, deploy API with provision endpoint, rebuild one node with Alpine, verify provision flow, confirm no data persists after reboot
- [ ] Phase 4 (optional): Weekly reboot schedule for periodic key rotation and state flush

## Design Decisions

1. **Fresh keypairs on every boot** — no private keys stored in API or on disk
2. **Provision-on-boot** — control plane is source of truth for peer lists
3. **Per-node agent tokens** — nodes self-provision without admin token
4. **Alpine diskless** — tmpfs root, SSD only for /boot, cost-neutral
5. **Terraform-based migration** — `node_configs` enables gradual rollout
