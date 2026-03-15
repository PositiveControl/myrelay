output "node_ips" {
  description = "Public IPv4 addresses of all VPN nodes"
  value       = hcloud_server.vpn_node[*].ipv4_address
}

output "node_names" {
  description = "Hostnames of all VPN nodes"
  value       = hcloud_server.vpn_node[*].name
}

output "node_ids" {
  description = "Hetzner server IDs of all VPN nodes"
  value       = hcloud_server.vpn_node[*].id
}
