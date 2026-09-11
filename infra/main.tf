resource "digitalocean_ssh_key" "deploy_key" {
  name       = "securelink-deploy-key"
  public_key = var.ssh_public_key
}

# --- US relay (nyc3 — closest DO equivalent to "Virginia"/US-East) ---
resource "digitalocean_droplet" "relay_us" {
  name     = "securelink-relay-us"
  region   = var.region_us
  size     = var.droplet_size
  image    = "ubuntu-22-04-x64"
  ssh_keys = [digitalocean_ssh_key.deploy_key.fingerprint]

  user_data = templatefile("${path.module}/cloud-init/wireguard-init.yaml.tpl", {
    management_api_token = var.management_api_token
    wireguard_port        = var.wireguard_port
    wg_subnet              = "10.8.0"
  })

  tags = ["securelink", "region-us"]
}

resource "digitalocean_firewall" "relay_us_fw" {
  name        = "securelink-relay-us-fw"
  droplet_ids = [digitalocean_droplet.relay_us.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "udp"
    port_range       = tostring(var.wireguard_port)
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  # SecureLink backend API (co-located here instead of a dedicated server —
  # see BUILD_GUIDE.md's deployment note). Client reaches this from anywhere.
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# --- Germany relay (fra1 — Frankfurt, literal Germany) ---
resource "digitalocean_droplet" "relay_germany" {
  name     = "securelink-relay-germany"
  region   = var.region_eu
  size     = var.droplet_size
  image    = "ubuntu-22-04-x64"
  ssh_keys = [digitalocean_ssh_key.deploy_key.fingerprint]

  user_data = templatefile("${path.module}/cloud-init/wireguard-init.yaml.tpl", {
    management_api_token = var.management_api_token
    wireguard_port        = var.wireguard_port
    wg_subnet              = "10.9.0"
  })

  tags = ["securelink", "region-germany"]
}

resource "digitalocean_firewall" "relay_germany_fw" {
  name        = "securelink-relay-germany-fw"
  droplet_ids = [digitalocean_droplet.relay_germany.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "udp"
    port_range       = tostring(var.wireguard_port)
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
