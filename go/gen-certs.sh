#!/usr/bin/env bash

ORG_ID=123
ASSET_ID=456
HOST="192.168.1.147"
PORT=5566

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# Root CA — 10-year validity, dev use only
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca.pem \
  -subj "/C=US/O=Wendy Labs Dev/CN=Wendy Dev Root CA"

# Server key + certificate signed by the root CA
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr \
  -subj "/C=US/O=Wendy Labs Dev/CN=localhost"
openssl x509 -req -days 825 -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server.pem \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:$HOST")

# Client (device) private key, CSR, and certificate signed by the root CA
openssl genrsa -out device-key.pem 2048
openssl req -new -key device-key.pem -out device.csr \
  -subj "/C=US/O=org-$ORG_ID/CN=device-$ASSET_ID"
openssl x509 -req -days 825 -in device.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out device.pem

# provisioning.json — dev state file consumed by wendy-agent's ProvisioningService
python3 - <<EOF
import json, os

def read(name):
    return open(name).read()

state = {
    "enrolled":  True,
    "cloudHost": "$HOST:$PORT",
    "orgId":     $ORG_ID,
    "assetId":   $ASSET_ID,
    "keyPem":    read("device-key.pem"),
    "certPem":   read("device.pem"),
    "chainPem":  read("ca.pem"),
}
path = "provisioning.json"
with open(path, "w") as f:
    json.dump(state, f, indent=2)
    f.write("\n")
print(f"wrote {path}")
EOF

# Sync to ESP-IDF component so files can be embedded in firmware
COMPONENT_CERTS="$SCRIPT_DIR/../components/wendy_cloud/certs"
cp provisioning.json "$COMPONENT_CERTS/"
echo "synced provisioning.json -> components/wendy_cloud/certs/"

echo ""
echo "Generated in $CERTS_DIR:"
ls -1
