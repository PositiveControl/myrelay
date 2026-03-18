# Single-node VPN example for Hetzner Cloud
#
# Usage:
#   export HCLOUD_TOKEN="your-token"
#   terraform init
#   terraform apply
#
# After provisioning, SSH in and run:
#   vpnctl peer add my-phone
#
# Then scan the QR code with the WireGuard app.

terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

variable "hcloud_token" {
  type      = string
  sensitive = true
}

variable "ssh_key_name" {
  type        = string
  description = "Name of your SSH key in Hetzner Cloud"
}

variable "location" {
  type        = string
  default     = "hel1"
  description = "Hetzner location (hel1=Helsinki, hil=Oregon, sin=Singapore, etc.)"
}

variable "server_type" {
  type    = string
  default = "cpx11"
}

data "hcloud_ssh_key" "default" {
  name = var.ssh_key_name
}

resource "hcloud_firewall" "vpn" {
  name = "vpn-firewall"

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    protocol  = "udp"
    port      = "51820"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_server" "vpn" {
  name        = "vpn-node"
  server_type = var.server_type
  location    = var.location
  image       = "ubuntu-24.04"
  ssh_keys    = [data.hcloud_ssh_key.default.id]
  firewall_ids = [hcloud_firewall.vpn.id]

  user_data = file("${path.module}/cloud-init.yaml")
}

output "server_ip" {
  value = hcloud_server.vpn.ipv4_address
}

output "ssh_command" {
  value = "ssh root@${hcloud_server.vpn.ipv4_address}"
}

output "next_steps" {
  value = <<-EOT
    1. SSH into your server: ssh root@${hcloud_server.vpn.ipv4_address}
    2. Wait for cloud-init to finish: cloud-init status --wait
    3. Add your first peer: vpnctl peer add my-phone
    4. Scan the QR code with the WireGuard app on your phone
  EOT
}
