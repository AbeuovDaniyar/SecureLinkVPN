terraform {
  required_version = ">= 1.6.0"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.34"
    }
  }
}

# Auth via env var (do not commit a token):
#   export DIGITALOCEAN_TOKEN="your-token-here"
# Generate a token at: https://cloud.digitalocean.com/account/api/tokens
provider "digitalocean" {}
