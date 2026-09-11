#cloud-config
package_update: true
packages:
  - wireguard
  - python3-pip
  - ufw

write_files:
  - path: /opt/relay-mgmt/app.py
    permissions: "0644"
    content: |
      # Minimal peer-management API for one WireGuard relay.
      # The backend calls this (over localhost via SSH tunnel, or
      # over a firewalled private port -- see BUILD_GUIDE.md Phase 2)
      # to add/remove peers instead of SSHing in and running `wg` by hand.
      import subprocess
      from flask import Flask, request, jsonify

      app = Flask(__name__)
      TOKEN = "${management_api_token}"
      INTERFACE = "wg0"

      def check_auth():
          auth = request.headers.get("Authorization", "")
          return auth == f"Bearer {TOKEN}"

      @app.route("/peers", methods=["POST"])
      def add_peer():
          if not check_auth():
              return jsonify({"error": "unauthorized"}), 401
          data = request.get_json(force=True)
          pubkey = data["publicKey"]
          allowed_ip = data["allowedIp"]  # e.g. "10.8.0.5/32"
          subprocess.run(
              ["wg", "set", INTERFACE, "peer", pubkey, "allowed-ips", allowed_ip],
              check=True,
          )
          return jsonify({"status": "added", "publicKey": pubkey, "allowedIp": allowed_ip})

      @app.route("/peers/remove", methods=["POST"])
      def remove_peer():
          # POST with the key in the JSON body, not DELETE /peers/<pubkey> --
          # WireGuard public keys are base64 and often contain a literal "/",
          # which breaks Flask's default single-segment path matching (a
          # DELETE for a key containing "/" 404s about half the time, since
          # roughly half of all base64 keys contain at least one "/").
          if not check_auth():
              return jsonify({"error": "unauthorized"}), 401
          data = request.get_json(force=True)
          pubkey = data["publicKey"]
          subprocess.run(["wg", "set", INTERFACE, "peer", pubkey, "remove"], check=True)
          return jsonify({"status": "removed", "publicKey": pubkey})

      @app.route("/health", methods=["GET"])
      def health():
          return jsonify({"status": "ok"})

      if __name__ == "__main__":
          app.run(host="127.0.0.1", port=8787)

  - path: /etc/systemd/system/relay-mgmt.service
    permissions: "0644"
    content: |
      [Unit]
      Description=SecureLink relay peer-management API
      After=network.target wg-quick@wg0.service

      [Service]
      ExecStart=/usr/bin/python3 /opt/relay-mgmt/app.py
      Restart=on-failure
      User=root

      [Install]
      WantedBy=multi-user.target

runcmd:
  - pip3 install flask
  # Enable IP forwarding so the relay can NAT tunnel traffic to the internet.
  - sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  - sysctl -p
  # Generate this relay's WireGuard keypair (private key never leaves this box).
  - umask 077 && wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
  - |
    cat > /etc/wireguard/wg0.conf <<EOF
    [Interface]
    Address = ${wg_subnet}.1/24
    ListenPort = ${wireguard_port}
    PrivateKey = $(cat /etc/wireguard/privatekey)
    PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
    EOF
  - systemctl enable wg-quick@wg0
  - systemctl start wg-quick@wg0
  - systemctl daemon-reload
  - systemctl enable relay-mgmt
  - systemctl start relay-mgmt
  # Firewall: allow SSH, WireGuard UDP; mgmt API stays on localhost only (127.0.0.1), reached via SSH tunnel.
  - ufw allow OpenSSH
  - ufw allow ${wireguard_port}/udp
  - ufw --force enable
  # ufw's default policy for routed/forwarded traffic is deny, which silently
  # drops everything a tunnel client tries to send onward to the internet even
  # with ip_forward=1 and the MASQUERADE rule above both correctly in place --
  # WireGuard's own handshake/keepalive still works (it terminates on this box,
  # so it never touches the FORWARD chain), which is what made this so easy to
  # miss: it looks like a working tunnel right up until someone actually tries
  # to browse through it. Without this, only the tunnel's own control traffic
  # ever works -- found the hard way once, don't remove without replacing it.
  - ufw route allow in on wg0 out on eth0
  - ufw reload

final_message: "SecureLink relay ready. SSH in and check: cat /etc/wireguard/publickey"
