# MyRelay Privacy Policy

**Last updated:** 2026-03-21

## Overview

MyRelay is a WireGuard-based VPN service. We are committed to protecting your privacy. This policy describes what data we collect, what we don't collect, and how we handle what we have.

## What we do NOT collect

- **No traffic logs.** We do not monitor, log, or inspect your VPN traffic.
- **No connection logs.** We do not record when you connect, disconnect, or how long you stay connected.
- **No DNS query logs.** We do not log DNS requests made through the VPN.
- **No IP address logs.** We do not record your source IP address or browsing activity.
- **No usage tracking.** We do not use analytics, tracking pixels, or third-party trackers.

This is enforced at the architecture level: VPN nodes run WireGuard with `SaveConfig = false` and no logging configuration. The control plane API has no access to traffic or connection data.

## What we collect

**Account data** (SaaS customers only):
- Email address — used for account identification and support
- Subscription plan — used for service provisioning
- WireGuard public key — provided by you, used to configure your VPN pod

**Infrastructure metrics** (not tied to individual users):
- Server health status (CPU, memory, uptime)
- Aggregate bandwidth per VPN interface — used for capacity planning
- Error logs from the API server — contain no user traffic data

## Architecture and isolation

Each customer gets a dedicated, kernel-isolated WireGuard interface (a "pod") on each subscribed node. The MyRelay control plane manages pod lifecycle (creation, deletion) but has zero visibility into what happens inside a pod. Your peers, your traffic, your rules.

## Data storage

- Account data is stored in an encrypted SQLite database on the API server
- WireGuard private keys are generated client-side. The server never sees your private key
- Node authentication tokens are stored as SHA-256 hashes

## Data retention

- Account data is retained while your account is active
- When you delete your account, all associated data (subscriptions, network rules, onboarding tokens) is permanently deleted via database cascading deletes
- VPN pod interfaces are destroyed on the nodes when your account is deleted
- We do not retain any data after account deletion because we have no traffic data to retain

## Third parties

We do not sell, share, or provide user data to any third party. Our infrastructure runs on Hetzner Cloud. Hetzner's own privacy policy applies to the hosting infrastructure.

## Self-hosted users

If you self-host MyRelay using the open-source software, this policy does not apply — you control your own data. The OSS software collects no telemetry and makes no external network requests.

## Changes

We will update this policy as needed. Material changes will be communicated to active customers via email.

## Contact

For privacy questions, contact the service administrator.
