#!/usr/bin/env bash
# Manual smoke test for a relay's peer-management API, run from your laptop
# over an SSH tunnel (the API only listens on 127.0.0.1 on the relay).
#
# Usage:
#   ssh -L 8787:127.0.0.1:8787 ubuntu@<relay-ip> -N &
#   ./test-add-peer.sh <management_api_token> <client_public_key> 10.8.0.5/32

set -euo pipefail

TOKEN="$1"
PUBKEY="$2"
ALLOWED_IP="$3"

curl -s -X POST http://127.0.0.1:8787/peers \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"publicKey\": \"${PUBKEY}\", \"allowedIp\": \"${ALLOWED_IP}\"}" | python3 -m json.tool
