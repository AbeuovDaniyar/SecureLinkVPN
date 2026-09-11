output "us_relay_ip" {
  value = digitalocean_droplet.relay_us.ipv4_address
}

output "germany_relay_ip" {
  value = digitalocean_droplet.relay_germany.ipv4_address
}

output "ssh_hint" {
  value = <<-EOT
    SSH in to fetch each relay's WireGuard public key (needed by the backend's Relays config):
      ssh root@${digitalocean_droplet.relay_us.ipv4_address} cat /etc/wireguard/publickey
      ssh root@${digitalocean_droplet.relay_germany.ipv4_address} cat /etc/wireguard/publickey

    DigitalOcean droplets log in as 'root' by default (unlike Lightsail's 'ubuntu' user).
  EOT
}
