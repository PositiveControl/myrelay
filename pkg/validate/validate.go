package validate

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
)

var ifaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

// WireGuardKey validates a WireGuard public or private key.
// Must be exactly 44 chars of valid base64 decoding to 32 bytes.
func WireGuardKey(key string) error {
	if len(key) != 44 {
		return fmt.Errorf("key must be exactly 44 characters, got %d", len(key))
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("key is not valid base64: %w", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("key must decode to 32 bytes, got %d", len(decoded))
	}
	return nil
}

// CIDR validates a CIDR notation string (e.g., "10.0.0.2/32").
func CIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}
	return nil
}

// InterfaceName validates a Linux network interface name.
func InterfaceName(name string) error {
	if !ifaceRegex.MatchString(name) {
		return fmt.Errorf("interface name must be 1-15 alphanumeric/dash/underscore characters")
	}
	return nil
}

// ListenPort validates a WireGuard listen port (1024-65535).
func ListenPort(port int) error {
	if port < 1024 || port > 65535 {
		return fmt.Errorf("listen port must be between 1024 and 65535, got %d", port)
	}
	return nil
}

// IP validates an IP address string.
func IP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}
