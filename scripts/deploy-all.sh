#!/bin/bash
# Deploy API and agent binaries with TLS certs to VPN nodes.
# Usage: ./scripts/deploy-all.sh
#
# Configure nodes by setting environment variables:
#   API_NODE_IP     — IP of the node running the API + agent
#   API_NODE_NAME   — Name/cert prefix for the API node (e.g., "vpn-us-west")
#   AGENT_NODES     — Comma-separated name=ip pairs for agent-only nodes
#                     (e.g., "vpn-ap-sgp=5.6.7.8,vpn-eu-fin=9.10.11.12")
#
# Example:
#   API_NODE_IP=1.2.3.4 API_NODE_NAME=vpn-us-west \
#   AGENT_NODES="vpn-ap-sgp=5.6.7.8" \
#   ./scripts/deploy-all.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

API_BINARY="${PROJECT_DIR}/bin/api"
AGENT_BINARY="${PROJECT_DIR}/bin/agent"
CERTS_DIR="${PROJECT_DIR}/certs"

if [ -z "${API_NODE_IP:-}" ] || [ -z "${API_NODE_NAME:-}" ]; then
    echo "ERROR: Set API_NODE_IP and API_NODE_NAME environment variables."
    echo "Example: API_NODE_IP=1.2.3.4 API_NODE_NAME=vpn-us-west ./scripts/deploy-all.sh"
    exit 1
fi

# Verify binaries exist
for bin in "$API_BINARY" "$AGENT_BINARY"; do
    if [ ! -f "$bin" ]; then
        echo "ERROR: $bin not found. Run: GOOS=linux GOARCH=amd64 make all"
        exit 1
    fi
done

# Verify certs exist for API node
for f in ca.crt "${API_NODE_NAME}.crt" "${API_NODE_NAME}.key"; do
    if [ ! -f "${CERTS_DIR}/${f}" ]; then
        echo "ERROR: ${CERTS_DIR}/${f} not found. Run: go run scripts/generate-certs.go -nodes \"${API_NODE_NAME}=${API_NODE_IP}\""
        exit 1
    fi
done

echo "=== Deploying to ${API_NODE_NAME} (${API_NODE_IP}) — API + Agent ==="

ssh ${SSH_OPTS} ${SSH_USER}@${API_NODE_IP} "systemctl stop vpn-api vpn-agent 2>/dev/null || true; mkdir -p /opt/vpn-api/certs /opt/vpn-agent/certs"

scp ${SSH_OPTS} "$API_BINARY" ${SSH_USER}@${API_NODE_IP}:/opt/vpn-api/api
scp ${SSH_OPTS} "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/${API_NODE_NAME}.crt" "${CERTS_DIR}/${API_NODE_NAME}.key" \
    ${SSH_USER}@${API_NODE_IP}:/opt/vpn-api/certs/

scp ${SSH_OPTS} "$AGENT_BINARY" ${SSH_USER}@${API_NODE_IP}:/opt/vpn-agent/agent
scp ${SSH_OPTS} "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/${API_NODE_NAME}.crt" "${CERTS_DIR}/${API_NODE_NAME}.key" \
    ${SSH_USER}@${API_NODE_IP}:/opt/vpn-agent/certs/

ssh ${SSH_OPTS} ${SSH_USER}@${API_NODE_IP} <<REMOTE
set -euo pipefail
chmod +x /opt/vpn-api/api /opt/vpn-agent/agent
chmod 600 /opt/vpn-api/certs/*.key /opt/vpn-agent/certs/*.key

cat > /etc/systemd/system/vpn-api.service <<SERVICE
[Unit]
Description=VPN Control Plane API
After=network.target

[Service]
Type=simple
ExecStart=/opt/vpn-api/api
Restart=always
RestartSec=5
EnvironmentFile=/opt/vpn-api/.env

[Install]
WantedBy=multi-user.target
SERVICE

grep -q TLS_CERT_FILE /opt/vpn-api/.env 2>/dev/null && sed -i '/^TLS_/d; /^SERVER_IP/d' /opt/vpn-api/.env
cat >> /opt/vpn-api/.env <<ENV
TLS_CERT_FILE=/opt/vpn-api/certs/${API_NODE_NAME}.crt
TLS_KEY_FILE=/opt/vpn-api/certs/${API_NODE_NAME}.key
SERVER_IP=${API_NODE_IP}
ENV

grep -q TLS_CERT_FILE /opt/vpn-agent/.env 2>/dev/null && sed -i '/^TLS_/d' /opt/vpn-agent/.env
cat >> /opt/vpn-agent/.env <<ENV
TLS_CERT_FILE=/opt/vpn-agent/certs/${API_NODE_NAME}.crt
TLS_KEY_FILE=/opt/vpn-agent/certs/${API_NODE_NAME}.key
TLS_CA_CERT=/opt/vpn-agent/certs/ca.crt
ENV

sed -i 's|API_URL=http://|API_URL=https://|' /opt/vpn-agent/.env

systemctl daemon-reload
systemctl restart vpn-api
sleep 2
systemctl restart vpn-agent
echo "${API_NODE_NAME}: API and agent restarted with TLS"
REMOTE

# Deploy agent-only nodes
if [ -n "${AGENT_NODES:-}" ]; then
    IFS=',' read -ra NODES <<< "$AGENT_NODES"
    for entry in "${NODES[@]}"; do
        NODE_NAME="${entry%%=*}"
        NODE_IP="${entry#*=}"

        echo ""
        echo "=== Deploying to ${NODE_NAME} (${NODE_IP}) — Agent only ==="

        for f in "${NODE_NAME}.crt" "${NODE_NAME}.key"; do
            if [ ! -f "${CERTS_DIR}/${f}" ]; then
                echo "ERROR: ${CERTS_DIR}/${f} not found."
                continue 2
            fi
        done

        ssh ${SSH_OPTS} ${SSH_USER}@${NODE_IP} "systemctl stop vpn-agent 2>/dev/null || true; mkdir -p /opt/vpn-agent/certs"
        scp ${SSH_OPTS} "$AGENT_BINARY" ${SSH_USER}@${NODE_IP}:/opt/vpn-agent/agent
        scp ${SSH_OPTS} "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/${NODE_NAME}.crt" "${CERTS_DIR}/${NODE_NAME}.key" \
            ${SSH_USER}@${NODE_IP}:/opt/vpn-agent/certs/

        ssh ${SSH_OPTS} ${SSH_USER}@${NODE_IP} <<REMOTE_AGENT
set -euo pipefail
chmod +x /opt/vpn-agent/agent
chmod 600 /opt/vpn-agent/certs/*.key

grep -q TLS_CERT_FILE /opt/vpn-agent/.env 2>/dev/null && sed -i '/^TLS_/d' /opt/vpn-agent/.env
cat >> /opt/vpn-agent/.env <<ENV
TLS_CERT_FILE=/opt/vpn-agent/certs/${NODE_NAME}.crt
TLS_KEY_FILE=/opt/vpn-agent/certs/${NODE_NAME}.key
TLS_CA_CERT=/opt/vpn-agent/certs/ca.crt
ENV

sed -i 's|API_URL=http://|API_URL=https://|' /opt/vpn-agent/.env
systemctl restart vpn-agent
echo "${NODE_NAME}: Agent restarted with TLS"
REMOTE_AGENT
    done
fi

echo ""
echo "=== Deployment complete ==="
echo "API:   https://${API_NODE_IP}:8080"
echo "To test: curl --cacert certs/ca.crt https://${API_NODE_IP}:8080/api/health"
