#!/bin/bash
# Deploy API and agent binaries with TLS certs to all VPN nodes.
# Usage: ./scripts/deploy-all.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

API_BINARY="${PROJECT_DIR}/bin/api"
AGENT_BINARY="${PROJECT_DIR}/bin/agent"
CERTS_DIR="${PROJECT_DIR}/certs"

# Verify binaries exist and are Linux ELF
for bin in "$API_BINARY" "$AGENT_BINARY"; do
    if [ ! -f "$bin" ]; then
        echo "ERROR: $bin not found. Run: GOOS=linux GOARCH=amd64 make all"
        exit 1
    fi
done

# Verify certs exist
for f in ca.crt vpn-us-west.crt vpn-us-west.key vpn-ap-sgp.crt vpn-ap-sgp.key; do
    if [ ! -f "${CERTS_DIR}/${f}" ]; then
        echo "ERROR: ${CERTS_DIR}/${f} not found. Run: go run scripts/generate-certs.go"
        exit 1
    fi
done

echo "=== Deploying to vpn-us-west (5.78.83.247) — API + Agent ==="

# Stop services and create cert directories
ssh ${SSH_OPTS} ${SSH_USER}@5.78.83.247 "systemctl stop vpn-api vpn-agent 2>/dev/null || true; mkdir -p /opt/vpn-api/certs /opt/vpn-agent/certs"

# Copy API binary and certs
scp ${SSH_OPTS} "$API_BINARY" ${SSH_USER}@5.78.83.247:/opt/vpn-api/api
scp ${SSH_OPTS} "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/vpn-us-west.crt" "${CERTS_DIR}/vpn-us-west.key" \
    ${SSH_USER}@5.78.83.247:/opt/vpn-api/certs/

# Copy agent binary and certs
scp ${SSH_OPTS} "$AGENT_BINARY" ${SSH_USER}@5.78.83.247:/opt/vpn-agent/agent
scp ${SSH_OPTS} "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/vpn-us-west.crt" "${CERTS_DIR}/vpn-us-west.key" \
    ${SSH_USER}@5.78.83.247:/opt/vpn-agent/certs/

# Set permissions and update systemd services
ssh ${SSH_OPTS} ${SSH_USER}@5.78.83.247 <<'REMOTE_US'
set -euo pipefail
chmod +x /opt/vpn-api/api /opt/vpn-agent/agent
chmod 600 /opt/vpn-api/certs/*.key /opt/vpn-agent/certs/*.key

# Update API service to use TLS
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

# Add TLS env vars to API .env (preserve existing vars)
grep -q TLS_CERT_FILE /opt/vpn-api/.env 2>/dev/null && sed -i '/^TLS_/d' /opt/vpn-api/.env
cat >> /opt/vpn-api/.env <<ENV
TLS_CERT_FILE=/opt/vpn-api/certs/vpn-us-west.crt
TLS_KEY_FILE=/opt/vpn-api/certs/vpn-us-west.key
SERVER_IP=5.78.83.247
ENV

# Add TLS env vars to agent .env (preserve existing vars)
grep -q TLS_CERT_FILE /opt/vpn-agent/.env 2>/dev/null && sed -i '/^TLS_/d' /opt/vpn-agent/.env
cat >> /opt/vpn-agent/.env <<ENV
TLS_CERT_FILE=/opt/vpn-agent/certs/vpn-us-west.crt
TLS_KEY_FILE=/opt/vpn-agent/certs/vpn-us-west.key
TLS_CA_CERT=/opt/vpn-agent/certs/ca.crt
ENV

# Also update API_URL in agent .env to use https
sed -i 's|API_URL=http://|API_URL=https://|' /opt/vpn-agent/.env

systemctl daemon-reload
systemctl restart vpn-api
sleep 2
systemctl restart vpn-agent
echo "vpn-us-west: API and agent restarted with TLS"
systemctl status vpn-api --no-pager -l | head -5
systemctl status vpn-agent --no-pager -l | head -5
REMOTE_US

echo ""
echo "=== Deploying to vpn-ap-sgp (5.223.70.143) — Agent only ==="

ssh ${SSH_OPTS} ${SSH_USER}@5.223.70.143 "systemctl stop vpn-agent 2>/dev/null || true; mkdir -p /opt/vpn-agent/certs"

scp ${SSH_OPTS} "$AGENT_BINARY" ${SSH_USER}@5.223.70.143:/opt/vpn-agent/agent
scp ${SSH_OPTS} "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/vpn-ap-sgp.crt" "${CERTS_DIR}/vpn-ap-sgp.key" \
    ${SSH_USER}@5.223.70.143:/opt/vpn-agent/certs/

ssh ${SSH_OPTS} ${SSH_USER}@5.223.70.143 <<'REMOTE_SGP'
set -euo pipefail
chmod +x /opt/vpn-agent/agent
chmod 600 /opt/vpn-agent/certs/*.key

# Add TLS env vars to agent .env
grep -q TLS_CERT_FILE /opt/vpn-agent/.env 2>/dev/null && sed -i '/^TLS_/d' /opt/vpn-agent/.env
cat >> /opt/vpn-agent/.env <<ENV
TLS_CERT_FILE=/opt/vpn-agent/certs/vpn-ap-sgp.crt
TLS_KEY_FILE=/opt/vpn-agent/certs/vpn-ap-sgp.key
TLS_CA_CERT=/opt/vpn-agent/certs/ca.crt
ENV

# Update API_URL to use https
sed -i 's|API_URL=http://|API_URL=https://|' /opt/vpn-agent/.env

systemctl restart vpn-agent
echo "vpn-ap-sgp: Agent restarted with TLS"
systemctl status vpn-agent --no-pager -l | head -5
REMOTE_SGP

echo ""
echo "=== Deployment complete ==="
echo "API:   https://5.78.83.247:8080"
echo "Agent: https://5.78.83.247:8081 (us-west)"
echo "Agent: https://5.223.70.143:8081 (ap-sgp)"
echo ""
echo "To test: curl --cacert certs/ca.crt https://5.78.83.247:8080/api/health"
