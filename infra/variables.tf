variable "droplet_size" {
  description = "s-1vcpu-1gb is plenty for a WireGuard relay — it just forwards encrypted packets."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "ssh_public_key" {
  description = "Your local SSH public key contents (e.g. contents of ~/.ssh/id_ed25519.pub), used to reach the relays for setup and debugging."
  type        = string
}

variable "management_api_token" {
  description = "Shared secret the backend uses to authenticate to each relay's local peer-management API. Generate with: openssl rand -hex 32"
  type        = string
  sensitive   = true
}

variable "wireguard_port" {
  description = "UDP port WireGuard listens on."
  type        = number
  default     = 51820
}

# NOTE on region naming: DigitalOcean has no region literally named "Virginia" —
# nyc1/nyc3 (New York) is the closest US-East equivalent by latency. If your
# design docs say "Virginia" specifically, update them to say "US-East (New
# York)" for accuracy — see BUILD_GUIDE.md Phase 1 note.
variable "region_us" {
  description = "DigitalOcean region slug for the US relay."
  type        = string
  default     = "nyc3"
}

variable "region_eu" {
  description = "DigitalOcean region slug for the Germany relay (fra1 = Frankfurt, literal Germany)."
  type        = string
  default     = "fra1"
}
