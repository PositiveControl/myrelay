#!/bin/bash
# Bootstrap script for new WireGuard VPN nodes.
# Intended to run as cloud-init user_data on Ubuntu 22.04.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "=== VPN Node Setup ==="

# Node subnet — each node gets a unique /24 (e.g., 10.0.1.0/24, 10.0.2.0/24).
# Set via cloud-init or environment. Defaults to 10.0.0.0/24 for standalone use.
WG_SUBNET="${WG_SUBNET:-10.0.0.1/24}"

# Update and install packages.
apt-get update -y
apt-get install -y wireguard wireguard-tools ufw fail2ban unattended-upgrades

# Enable automatic security updates.
cat > /etc/apt/apt.conf.d/20auto-upgrades <<AUTOUPGRADE
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
AUTOUPGRADE
systemctl enable unattended-upgrades

# Enable IP forwarding.
cat > /etc/sysctl.d/99-wireguard.conf <<SYSCTL
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
SYSCTL
sysctl --system

# Determine the primary public network interface.
PUBLIC_IFACE=$(ip route show default | awk '{print $5}' | head -1)
echo "Detected public interface: ${PUBLIC_IFACE}"

# Generate server WireGuard keys.
umask 077
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
SERVER_PRIVKEY=$(cat /etc/wireguard/server.key)

# Create initial WireGuard config (no peers yet; the agent manages peers).
cat > /etc/wireguard/wg0.conf <<WG
[Interface]
PrivateKey = ${SERVER_PRIVKEY}
Address = ${WG_SUBNET}
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${PUBLIC_IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${PUBLIC_IFACE} -j MASQUERADE
SaveConfig = false
WG

chmod 600 /etc/wireguard/wg0.conf

# Enable and start WireGuard.
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Harden SSH.
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart sshd

# Create deploy user with sudo for agent management.
if ! id deploy &>/dev/null; then
    useradd -m -s /bin/bash deploy
    mkdir -p /home/deploy/.ssh
    # Copy root's authorized_keys for initial access.
    cp /root/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys
    chown -R deploy:deploy /home/deploy/.ssh
    chmod 700 /home/deploy/.ssh
    chmod 600 /home/deploy/.ssh/authorized_keys
    echo "deploy ALL=(root) NOPASSWD: /bin/systemctl restart vpn-agent, /bin/systemctl restart vpn-api, /bin/cp" > /etc/sudoers.d/deploy
    chmod 440 /etc/sudoers.d/deploy
fi

# Configure fail2ban for SSH.
cat > /etc/fail2ban/jail.local <<F2B
[sshd]
enabled = true
port = ssh
maxretry = 5
bantime = 3600
F2B
systemctl enable fail2ban
systemctl start fail2ban

# Configure UFW firewall.
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH"
ufw allow 51820/udp comment "WireGuard"
ufw allow 8081/tcp comment "VPN Agent API"
ufw --force enable

# Create a directory for the agent binary.
mkdir -p /opt/vpn-agent

# Create a systemd service for the agent.
cat > /etc/systemd/system/vpn-agent.service <<SERVICE
[Unit]
Description=VPN Node Agent
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/opt/vpn-agent/agent -interface wg0
Restart=always
RestartSec=5
EnvironmentFile=/opt/vpn-agent/.env

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable vpn-agent.service

echo "=== VPN Node Setup Complete ==="
echo "Server public key: $(cat /etc/wireguard/server.pub)"
