resource "hcloud_firewall" "vpn_node" {
  name = "vpn-node-firewall"

  # SSH — consider restricting to management IPs later
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "SSH access"
  }

  # WireGuard
  rule {
    direction   = "in"
    protocol    = "udp"
    port        = "51820"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "WireGuard VPN"
  }

  # API — restricted to admin IPs
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "8080"
    source_ips  = var.admin_cidrs
    description = "Control plane API (admin only)"
  }

  # Agent — restricted to VPN node IPs only
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "8081"
    source_ips  = var.agent_source_cidrs
    description = "Agent API (inter-node only)"
  }

  labels = {
    managed = "terraform"
    role    = "vpn"
  }
}
