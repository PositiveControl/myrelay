package wireguard

import (
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
)

// ComputeAllowedIPs returns the AllowedIPs string that covers all of 0.0.0.0/0
// except the given excluded CIDRs. If no CIDRs are excluded, returns "0.0.0.0/0".
func ComputeAllowedIPs(excludedCIDRs []string) (string, error) {
	if len(excludedCIDRs) == 0 {
		return "0.0.0.0/0", nil
	}

	// Start with 0.0.0.0/0
	_, universe, _ := net.ParseCIDR("0.0.0.0/0")
	result := []*net.IPNet{universe}

	for _, cidr := range excludedCIDRs {
		_, exclude, err := net.ParseCIDR(cidr)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}

		var next []*net.IPNet
		for _, r := range result {
			subtracted := subtractCIDR(r, exclude)
			next = append(next, subtracted...)
		}
		result = next
	}

	// Sort by IP then mask length for deterministic output
	sort.Slice(result, func(i, j int) bool {
		cmp := ipToInt(result[i].IP).Cmp(ipToInt(result[j].IP))
		if cmp != 0 {
			return cmp < 0
		}
		iOnes, _ := result[i].Mask.Size()
		jOnes, _ := result[j].Mask.Size()
		return iOnes < jOnes
	})

	parts := make([]string, len(result))
	for i, r := range result {
		parts[i] = r.String()
	}
	return strings.Join(parts, ", "), nil
}

// subtractCIDR removes the 'exclude' network from 'parent'.
// If they don't overlap, returns [parent]. If exclude fully covers parent, returns [].
// Otherwise, splits parent into sub-CIDRs that don't overlap with exclude.
func subtractCIDR(parent, exclude *net.IPNet) []*net.IPNet {
	if !parent.Contains(exclude.IP) && !exclude.Contains(parent.IP) {
		// No overlap
		return []*net.IPNet{parent}
	}

	parentOnes, parentBits := parent.Mask.Size()
	excludeOnes, _ := exclude.Mask.Size()

	// If exclude fully covers parent
	if excludeOnes <= parentOnes && exclude.Contains(parent.IP) {
		return nil
	}

	// Split parent into two halves, recurse on each
	if parentOnes >= parentBits {
		// Can't split further — single host
		if exclude.Contains(parent.IP) {
			return nil
		}
		return []*net.IPNet{parent}
	}

	left, right := splitCIDR(parent)

	var result []*net.IPNet
	result = append(result, subtractCIDR(left, exclude)...)
	result = append(result, subtractCIDR(right, exclude)...)
	return result
}

// splitCIDR splits a CIDR block into its two halves (one bit longer prefix).
func splitCIDR(cidr *net.IPNet) (*net.IPNet, *net.IPNet) {
	ones, bits := cidr.Mask.Size()
	newOnes := ones + 1

	// Left half: same network address, longer prefix
	leftIP := make(net.IP, len(cidr.IP))
	copy(leftIP, cidr.IP)
	leftMask := net.CIDRMask(newOnes, bits)
	left := &net.IPNet{IP: leftIP.Mask(leftMask), Mask: leftMask}

	// Right half: set the bit at position 'ones' to 1
	rightIP := make(net.IP, len(cidr.IP))
	copy(rightIP, cidr.IP)
	setBit(rightIP, ones)
	rightMask := net.CIDRMask(newOnes, bits)
	right := &net.IPNet{IP: rightIP.Mask(rightMask), Mask: rightMask}

	return left, right
}

// setBit sets the nth bit (0-indexed from MSB) of an IP address.
func setBit(ip net.IP, n int) {
	ip4 := ip.To4()
	if ip4 != nil {
		ip = ip4
	}
	byteIndex := n / 8
	bitIndex := 7 - (n % 8)
	ip[byteIndex] |= 1 << uint(bitIndex)
}

// ipToInt converts an IP to a big.Int for sorting.
func ipToInt(ip net.IP) *big.Int {
	ip4 := ip.To4()
	if ip4 != nil {
		return new(big.Int).SetBytes(ip4)
	}
	return new(big.Int).SetBytes(ip)
}
