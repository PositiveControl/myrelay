variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "node_count" {
  description = "Number of WireGuard VPN nodes to create"
  type        = number
  default     = 2
}

variable "server_type" {
  description = "Hetzner server type for VPN nodes"
  type        = string
  default     = "cx22"
}

variable "location" {
  description = "Hetzner datacenter location"
  type        = string
  default     = "nbg1"
}

variable "ssh_key_name" {
  description = "Name of the SSH key in Hetzner Cloud to use for node access"
  type        = string
}

variable "image" {
  description = "OS image for VPN nodes"
  type        = string
  default     = "ubuntu-22.04"
}

variable "node_name_prefix" {
  description = "Prefix for VPN node hostnames"
  type        = string
  default     = "vpn"
}
