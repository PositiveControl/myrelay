data "hcloud_ssh_key" "default" {
  name = var.ssh_key_name
}

resource "hcloud_server" "vpn_node" {
  count       = var.node_count
  name        = "${var.node_name_prefix}-${count.index + 1}"
  server_type = var.server_type
  image       = var.image
  location    = var.location

  ssh_keys = [data.hcloud_ssh_key.default.id]

  user_data = file("${path.module}/../scripts/setup-node.sh")

  labels = {
    role    = "vpn"
    managed = "terraform"
  }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  lifecycle {
    create_before_destroy = true
  }
}
