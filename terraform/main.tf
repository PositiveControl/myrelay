terraform {
  required_version = ">= 1.5.0"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }

  # Uncomment and configure for remote state:
  # backend "s3" {
  #   bucket = "vpn-terraform-state"
  #   key    = "terraform.tfstate"
  #   region = "eu-central-1"
  # }
}

provider "hcloud" {
  token = var.hcloud_token
}
