package models

// NetworkRule defines a network that should be excluded from (or included in) the VPN tunnel.
type NetworkRule struct {
	ID      string `json:"id"`
	UserID  string `json:"user_id"`
	Name    string `json:"name"`
	Network string `json:"network"` // CIDR notation, e.g. "192.168.1.0/24"
	Action  string `json:"action"`  // "bypass" = exclude from VPN
}
