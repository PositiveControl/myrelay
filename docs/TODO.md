# TODO

## OSS Features

### Lightweight control plane
Multi-node management for self-hosted users. A single admin running several nodes (e.g., for family/friends) should be able to view and manage all nodes from one place without needing the SaaS product. Likely a thin aggregation layer over the existing agent APIs on each node, with a CLI (`vpnctl nodes list`, etc.).

### Peer mesh networking
Optional peer-to-peer connectivity between VPN clients. Instead of all traffic routing through the server (hub-and-spoke), peers can reach each other directly. Enables use cases like accessing a family member's NAS, home devices, etc. Similar to what Tailscale/Netmaker offer.
