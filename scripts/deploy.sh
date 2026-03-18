#!/bin/bash
# Full deployment pipeline: build, generate certs, deploy, and register nodes.
#
# Usage:
#   ./scripts/deploy.sh                  # Deploy to all nodes from terraform
#   ./scripts/deploy.sh vpn-eu-fin       # Deploy to a specific node only
#
# Reads node info from terraform output. Requires:
#   - .env file with VPN_API_URL and VPN_ADMIN_TOKEN
#   - terraform state with node IPs
#
# What it does:
#   1. Cross-compiles API + agent binaries for linux/amd64
#   2. Generates TLS certs for any node missing them
#   3. Deploys binaries + certs to each node via SSH
#   4. Configures agent .env and systemd service
#   5. Registers new nodes with the control plane API
#   6. Restarts services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SSH_USER="${SSH_USER:-root}"
CERTS_DIR="${PROJECT_DIR}/certs"
TARGET_NODE="${1:-}"

cd "$PROJECT_DIR"

# Load .env for API access
if [ -f .env ]; then
    source .env
fi
if [ -z "${VPN_API_URL:-}" ] || [ -z "${VPN_ADMIN_TOKEN:-}" ]; then
    echo "ERROR: .env must set VPN_API_URL and VPN_ADMIN_TOKEN"
    exit 1
fi

# --- Step 1: Cross-compile ---
echo "=== Building binaries for linux/amd64 ==="
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o bin/api-linux ./cmd/api
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o bin/agent-linux ./cmd/agent
echo "Built bin/api-linux and bin/agent-linux"

# --- Step 2: Read nodes from terraform ---
echo ""
echo "=== Reading node info from terraform ==="
cd terraform
NODES_JSON=$(terraform output -json nodes 2>/dev/null)
cd "$PROJECT_DIR"

if [ -z "$NODES_JSON" ] || [ "$NODES_JSON" = "{}" ]; then
    echo "ERROR: No nodes found in terraform output"
    exit 1
fi

# Parse into arrays
NODE_NAMES=($(echo "$NODES_JSON" | jq -r 'keys[]'))
echo "Found ${#NODE_NAMES[@]} node(s): ${NODE_NAMES[*]}"

# Detect which node runs the API (the one whose IP matches VPN_API_URL)
API_IP=$(echo "$VPN_API_URL" | sed -E 's|https?://([^:]+).*|\1|')
API_NODE_NAME=""
for name in "${NODE_NAMES[@]}"; do
    ip=$(echo "$NODES_JSON" | jq -r ".\"$name\".ip")
    if [ "$ip" = "$API_IP" ]; then
        API_NODE_NAME="$name"
        break
    fi
done
if [ -n "$API_NODE_NAME" ]; then
    echo "API node: ${API_NODE_NAME} (${API_IP})"
else
    echo "Warning: Could not detect API node from VPN_API_URL=${VPN_API_URL}"
fi

# --- Step 3: Generate missing certs ---
echo ""
echo "=== Checking TLS certificates ==="
MISSING_CERTS=""
for name in "${NODE_NAMES[@]}"; do
    if [ -n "$TARGET_NODE" ] && [ "$name" != "$TARGET_NODE" ]; then
        continue
    fi
    if [ ! -f "${CERTS_DIR}/${name}.crt" ] || [ ! -f "${CERTS_DIR}/${name}.key" ]; then
        ip=$(echo "$NODES_JSON" | jq -r ".\"$name\".ip")
        if [ -n "$MISSING_CERTS" ]; then
            MISSING_CERTS="${MISSING_CERTS},${name}=${ip}"
        else
            MISSING_CERTS="${name}=${ip}"
        fi
    fi
done

if [ -n "$MISSING_CERTS" ]; then
    echo "Generating certs for: ${MISSING_CERTS}"
    go run scripts/generate-certs.go -nodes "$MISSING_CERTS"
else
    echo "All certs present"
fi

# --- Step 4: Deploy to each node ---
for name in "${NODE_NAMES[@]}"; do
    if [ -n "$TARGET_NODE" ] && [ "$name" != "$TARGET_NODE" ]; then
        continue
    fi

    ip=$(echo "$NODES_JSON" | jq -r ".\"$name\".ip")
    echo ""

    if [ "$name" = "$API_NODE_NAME" ]; then
        echo "=== Deploying to ${name} (${ip}) — API + Agent ==="

        ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" \
            "systemctl stop vpn-api vpn-agent 2>/dev/null || true; mkdir -p /opt/vpn-api/certs /opt/vpn-agent/certs"

        scp -o StrictHostKeyChecking=no bin/api-linux "$SSH_USER@$ip:/opt/vpn-api/api"
        scp -o StrictHostKeyChecking=no bin/agent-linux "$SSH_USER@$ip:/opt/vpn-agent/agent"
        scp -o StrictHostKeyChecking=no "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/${name}.crt" "${CERTS_DIR}/${name}.key" \
            "$SSH_USER@$ip:/opt/vpn-api/certs/"
        scp -o StrictHostKeyChecking=no "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/${name}.crt" "${CERTS_DIR}/${name}.key" \
            "$SSH_USER@$ip:/opt/vpn-agent/certs/"

        ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" bash -s "$name" "$ip" <<'REMOTE_API'
            set -euo pipefail
            NODE_NAME="$1"; NODE_IP="$2"
            chmod +x /opt/vpn-api/api /opt/vpn-agent/agent
            chmod 600 /opt/vpn-api/certs/*.key /opt/vpn-agent/certs/*.key

            # API systemd service
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

            # Update TLS vars in API .env
            sed -i '/^TLS_/d; /^SERVER_IP/d' /opt/vpn-api/.env 2>/dev/null || true
            cat >> /opt/vpn-api/.env <<ENV
TLS_CERT_FILE=/opt/vpn-api/certs/${NODE_NAME}.crt
TLS_KEY_FILE=/opt/vpn-api/certs/${NODE_NAME}.key
SERVER_IP=${NODE_IP}
ENV

            # Update TLS vars in agent .env
            sed -i '/^TLS_/d' /opt/vpn-agent/.env 2>/dev/null || true
            cat >> /opt/vpn-agent/.env <<ENV
TLS_CERT_FILE=/opt/vpn-agent/certs/${NODE_NAME}.crt
TLS_KEY_FILE=/opt/vpn-agent/certs/${NODE_NAME}.key
TLS_CA_CERT=/opt/vpn-agent/certs/ca.crt
ENV
            # Ensure AGENT_MODE is set
            grep -q '^AGENT_MODE=' /opt/vpn-agent/.env || echo "AGENT_MODE=managed" >> /opt/vpn-agent/.env
            sed -i 's|API_URL=http://|API_URL=https://|' /opt/vpn-agent/.env

            systemctl daemon-reload
            systemctl restart vpn-api
            sleep 2
            systemctl restart vpn-agent
            echo "${NODE_NAME}: API + agent restarted"
REMOTE_API

    else
        echo "=== Deploying to ${name} (${ip}) — Agent only ==="

        ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" \
            "systemctl stop vpn-agent 2>/dev/null || true; mkdir -p /opt/vpn-agent/certs"

        scp -o StrictHostKeyChecking=no bin/agent-linux "$SSH_USER@$ip:/opt/vpn-agent/agent"
        scp -o StrictHostKeyChecking=no "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/${name}.crt" "${CERTS_DIR}/${name}.key" \
            "$SSH_USER@$ip:/opt/vpn-agent/certs/"

        # Check if this node is already registered with the API
        NODE_EXISTS=$(curl -s --cacert "${CERTS_DIR}/ca.crt" \
            -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer ${VPN_ADMIN_TOKEN}" \
            "${VPN_API_URL}/api/nodes/${name}" 2>/dev/null || echo "000")

        AGENT_TOKEN=""
        if [ "$NODE_EXISTS" != "200" ]; then
            echo "Registering ${name} with control plane..."
            WG_PUBKEY=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" "cat /etc/wireguard/server.pub")
            REGISTER_RESP=$(curl -s --cacert "${CERTS_DIR}/ca.crt" \
                -X POST "${VPN_API_URL}/api/nodes" \
                -H "Authorization: Bearer ${VPN_ADMIN_TOKEN}" \
                -H "Content-Type: application/json" \
                -d "{\"id\":\"${name}\",\"name\":\"${name}\",\"ip\":\"${ip}\",\"region\":\"$(echo "$NODES_JSON" | jq -r ".\"$name\".location")\",\"public_key\":\"${WG_PUBKEY}\"}")
            AGENT_TOKEN=$(echo "$REGISTER_RESP" | jq -r '.agent_token // empty')
            if [ -n "$AGENT_TOKEN" ]; then
                echo "Registered. Agent token obtained."
            else
                echo "WARNING: Registration response: ${REGISTER_RESP}"
            fi
        else
            echo "Node already registered with API"
        fi

        ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" bash -s "$name" "$VPN_API_URL" "$AGENT_TOKEN" <<'REMOTE_AGENT'
            set -euo pipefail
            NODE_NAME="$1"; API_URL="$2"; NEW_TOKEN="$3"
            chmod +x /opt/vpn-agent/agent
            chmod 600 /opt/vpn-agent/certs/*.key

            # Create .env if it doesn't exist
            if [ ! -f /opt/vpn-agent/.env ]; then
                cat > /opt/vpn-agent/.env <<ENV
AGENT_MODE=managed
API_URL=${API_URL}
NODE_ID=${NODE_NAME}
WG_INTERFACE=wg0
AGENT_LISTEN=:8081
ENV
            fi

            # Set agent token if we got a new one from registration
            if [ -n "$NEW_TOKEN" ]; then
                sed -i '/^AGENT_TOKEN=/d' /opt/vpn-agent/.env
                echo "AGENT_TOKEN=${NEW_TOKEN}" >> /opt/vpn-agent/.env
            fi

            # Ensure mode is managed
            grep -q '^AGENT_MODE=' /opt/vpn-agent/.env || echo "AGENT_MODE=managed" >> /opt/vpn-agent/.env

            # Update TLS vars
            sed -i '/^TLS_/d' /opt/vpn-agent/.env 2>/dev/null || true
            cat >> /opt/vpn-agent/.env <<ENV
TLS_CERT_FILE=/opt/vpn-agent/certs/${NODE_NAME}.crt
TLS_KEY_FILE=/opt/vpn-agent/certs/${NODE_NAME}.key
TLS_CA_CERT=/opt/vpn-agent/certs/ca.crt
ENV

            # Systemd service
            cat > /etc/systemd/system/vpn-agent.service <<SERVICE
[Unit]
Description=VPN Agent (managed)
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service
[Service]
Type=simple
ExecStart=/opt/vpn-agent/agent -mode managed -interface wg0
EnvironmentFile=/opt/vpn-agent/.env
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SERVICE

            systemctl daemon-reload
            systemctl enable vpn-agent
            systemctl restart vpn-agent
            echo "${NODE_NAME}: Agent restarted"
REMOTE_AGENT
    fi
done

# --- Step 5: Verify ---
echo ""
echo "=== Verifying cluster ==="
sleep 3
NODES_STATUS=$(curl -s --cacert "${CERTS_DIR}/ca.crt" \
    -H "Authorization: Bearer ${VPN_ADMIN_TOKEN}" \
    "${VPN_API_URL}/api/nodes" 2>/dev/null)

echo "$NODES_STATUS" | jq -r '.[] | "\(.id)\t\(.ip)\t\(.region)\t\(.current_peers)/\(.max_peers)\t\(.status)"' | \
    (echo -e "NODE\tIP\tREGION\tPEERS\tSTATUS" && cat) | column -t

echo ""
echo "=== Deployment complete ==="
