data "hcloud_ssh_key" "default" {
  name = var.ssh_key_name
}

resource "hcloud_server" "vpn_node" {
  for_each = var.nodes

  name        = each.key
  server_type = each.value.server_type
  image       = var.image
  location    = each.value.location

  ssh_keys = [data.hcloud_ssh_key.default.id]

  user_data = file("${path.module}/../scripts/setup-node.sh")

  labels = {
    role     = "vpn"
    managed  = "terraform"
    location = each.value.location
  }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  lifecycle {
    create_before_destroy = true
  }
}
