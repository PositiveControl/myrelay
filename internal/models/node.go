package models

// NodeStatus represents the operational state of a VPN node.
type NodeStatus string

const (
	NodeStatusProvisioning NodeStatus = "provisioning"
	NodeStatusActive       NodeStatus = "active"
	NodeStatusDraining     NodeStatus = "draining"
	NodeStatusOffline      NodeStatus = "offline"
)

// Node represents a WireGuard VPN server node.
type Node struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	IP           string     `json:"ip"`
	Region       string     `json:"region"`
	PublicKey    string     `json:"public_key"`
	Endpoint     string     `json:"endpoint"`
	MaxPeers     int        `json:"max_peers"`
	CurrentPeers int        `json:"current_peers"`
	Status       NodeStatus `json:"status"`
}

// HasCapacity returns true if the node can accept more peers.
func (n *Node) HasCapacity() bool {
	return n.CurrentPeers < n.MaxPeers && n.Status == NodeStatusActive
}

// UsagePercent returns peer utilization as a percentage (0-100).
func (n *Node) UsagePercent() float64 {
	if n.MaxPeers == 0 {
		return 100
	}
	return float64(n.CurrentPeers) / float64(n.MaxPeers) * 100
}

// WireGuardEndpoint returns the full endpoint string for client configs.
func (n *Node) WireGuardEndpoint() string {
	if n.Endpoint != "" {
		return n.Endpoint
	}
	return n.IP + ":51820"
}
