package wireguard

import (
	"net"
	"strings"
	"testing"
)

func TestComputeAllowedIPs_NoExclusions(t *testing.T) {
	result, err := ComputeAllowedIPs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "0.0.0.0/0" {
		t.Fatalf("expected 0.0.0.0/0, got %s", result)
	}
}

func TestComputeAllowedIPs_ExcludeOne(t *testing.T) {
	result, err := ComputeAllowedIPs([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the excluded network is not covered
	cidrs := strings.Split(result, ", ")
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("invalid CIDR in result: %s", cidr)
		}
		// No result range should contain any IP in 192.168.1.0/24
		if ipNet.Contains(net.ParseIP("192.168.1.1")) {
			t.Fatalf("result CIDR %s contains excluded IP 192.168.1.1", cidr)
		}
		if ipNet.Contains(net.ParseIP("192.168.1.254")) {
			t.Fatalf("result CIDR %s contains excluded IP 192.168.1.254", cidr)
		}
	}

	// Verify some IPs outside the exclusion ARE covered
	mustContain := []string{"10.0.0.1", "8.8.8.8", "1.1.1.1", "192.168.0.1", "192.168.2.1"}
	for _, ipStr := range mustContain {
		ip := net.ParseIP(ipStr)
		found := false
		for _, cidr := range cidrs {
			_, ipNet, _ := net.ParseCIDR(cidr)
			if ipNet.Contains(ip) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("IP %s should be covered by AllowedIPs but isn't", ipStr)
		}
	}
}

func TestComputeAllowedIPs_ExcludeMultiple(t *testing.T) {
	result, err := ComputeAllowedIPs([]string{"192.168.1.0/24", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cidrs := strings.Split(result, ", ")

	// Neither excluded network should be covered
	excludedIPs := []string{"192.168.1.50", "10.1.2.3", "10.255.255.255"}
	for _, ipStr := range excludedIPs {
		ip := net.ParseIP(ipStr)
		for _, cidr := range cidrs {
			_, ipNet, _ := net.ParseCIDR(cidr)
			if ipNet.Contains(ip) {
				t.Fatalf("result CIDR %s contains excluded IP %s", cidr, ipStr)
			}
		}
	}

	// IPs outside both exclusions should be covered
	mustContain := []string{"8.8.8.8", "172.16.0.1", "192.168.2.1"}
	for _, ipStr := range mustContain {
		ip := net.ParseIP(ipStr)
		found := false
		for _, cidr := range cidrs {
			_, ipNet, _ := net.ParseCIDR(cidr)
			if ipNet.Contains(ip) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("IP %s should be covered but isn't", ipStr)
		}
	}
}

func TestComputeAllowedIPs_InvalidCIDR(t *testing.T) {
	_, err := ComputeAllowedIPs([]string{"not-a-cidr"})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestComputeAllowedIPs_ExcludeEverything(t *testing.T) {
	result, err := ComputeAllowedIPs([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Fatalf("expected empty result, got %s", result)
	}
}
