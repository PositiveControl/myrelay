variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "nodes" {
  description = "Map of VPN nodes to create. Key is the node name."
  type = map(object({
    location    = string
    server_type = optional(string, "cpx12")
  }))
  default = {
    "vpn-us-west" = { location = "hil", server_type = "cpx11" }
    "vpn-eu-fin"  = { location = "hel1", server_type = "cpx11" }
    "vpn-ap-sgp"  = { location = "sin", server_type = "cpx12" }
  }
}

variable "ssh_key_name" {
  description = "Name of the SSH key in Hetzner Cloud to use for node access"
  type        = string
}

variable "image" {
  description = "OS image for VPN nodes"
  type        = string
  default     = "ubuntu-24.04"
}

variable "admin_cidrs" {
  description = "CIDRs allowed to access the API on port 8080"
  type        = list(string)
  # Set this to your own IP. Example: ["203.0.113.1/32"]
}

variable "agent_source_cidrs" {
  description = "CIDRs allowed to access the agent API on port 8081 (VPN node IPs + API server IP)"
  type        = list(string)
  default     = []
}
