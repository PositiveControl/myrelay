package models

// NodeStatus represents the operational state of a VPN node.
type NodeStatus string

const (
	NodeStatusProvisioning NodeStatus = "provisioning"
	NodeStatusActive       NodeStatus = "active"
	NodeStatusDraining     NodeStatus = "draining"
	NodeStatusOffline      NodeStatus = "offline"
)

// NodeMode represents the assignment model for a VPN node.
type NodeMode string

const (
	NodeModeDedicated NodeMode = "dedicated"
	NodeModeShared    NodeMode = "shared"
)

// Node represents a WireGuard VPN server node.
// In the dedicated-node model, each node is owned by a single customer.
type Node struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	IP           string     `json:"ip"`
	Region       string     `json:"region"`
	Subnet       string     `json:"subnet"`
	PublicKey    string     `json:"public_key"`
	Endpoint     string     `json:"endpoint"`
	OwnerID      string     `json:"owner_id"`
	ProviderID   string     `json:"provider_id"`
	ProviderType string     `json:"provider_type"`
	MaxPeers     int        `json:"max_peers"`
	NextPeerIP   int        `json:"next_peer_ip"`
	Status       NodeStatus `json:"status"`
	Mode         NodeMode   `json:"mode"`
}

// IsDedicated returns true if the node is owned by a customer.
func (n *Node) IsDedicated() bool {
	return n.OwnerID != ""
}

// IsAvailable returns true if the node is active and unowned.
func (n *Node) IsAvailable() bool {
	return n.OwnerID == "" && n.Status == NodeStatusActive
}

// IsDedicatedAvailable returns true if this is a dedicated-mode node
// that is active and not yet assigned to a customer.
func (n *Node) IsDedicatedAvailable() bool {
	return n.Mode == NodeModeDedicated && n.OwnerID == "" && n.Status == NodeStatusActive
}

// HasCapacity returns true if the node can accept more peers.
// A max_peers of 0 means unlimited.
func (n *Node) HasCapacity(currentPeers int) bool {
	return n.MaxPeers == 0 || currentPeers < n.MaxPeers
}

// WireGuardEndpoint returns the full endpoint string for client configs.
func (n *Node) WireGuardEndpoint() string {
	if n.Endpoint != "" {
		return n.Endpoint
	}
	return n.IP + ":51820"
}
