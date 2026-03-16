#!/bin/bash
# Deploy the agent binary to all VPN nodes.
# Usage: ./scripts/deploy-agent.sh [node_ip ...]
# If no IPs given, reads from terraform output.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
AGENT_BINARY="${PROJECT_DIR}/bin/agent"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

if [ ! -f "$AGENT_BINARY" ]; then
    echo "Agent binary not found at ${AGENT_BINARY}"
    echo "Run 'make build-agent' first (with GOOS=linux GOARCH=amd64 for remote nodes)."
    exit 1
fi

# Get node IPs from arguments or terraform.
if [ $# -gt 0 ]; then
    NODE_IPS=("$@")
else
    echo "Fetching node IPs from Terraform..."
    cd "${PROJECT_DIR}/terraform"
    NODE_IPS=($(terraform output -json nodes | jq -r '.[].ip'))
fi

if [ ${#NODE_IPS[@]} -eq 0 ]; then
    echo "No node IPs found."
    exit 1
fi

echo "Deploying agent to ${#NODE_IPS[@]} node(s)..."

for ip in "${NODE_IPS[@]}"; do
    echo ""
    echo "--- Deploying to ${ip} ---"

    # Copy the binary.
    scp ${SSH_OPTS} "$AGENT_BINARY" "${SSH_USER}@${ip}:/opt/vpn-agent/agent"

    # Restart the agent service.
    ssh ${SSH_OPTS} "${SSH_USER}@${ip}" "chmod +x /opt/vpn-agent/agent && systemctl restart vpn-agent"

    echo "Deployed and restarted agent on ${ip}"
done

echo ""
echo "=== Deployment complete ==="
