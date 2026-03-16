output "nodes" {
  description = "All VPN node details"
  value = {
    for name, server in hcloud_server.vpn_node : name => {
      id       = server.id
      ip       = server.ipv4_address
      ipv6     = server.ipv6_address
      location = var.nodes[name].location
      status   = server.status
    }
  }
}
