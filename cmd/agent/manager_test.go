package main

import "testing"

// TestNatSubnet covers the address-to-subnet derivation used on teardown. A
// wrong answer here is expensive: a catch-all subnet makes DestroyInterface
// delete the node-wide MASQUERADE rule, cutting egress for every peer on the
// host rather than just the interface being destroyed.
func TestNatSubnet(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{"typical interface address", "10.0.0.1/24", "10.0.0.0/24"},
		{"single host", "10.0.0.1/32", "10.0.0.1/32"},
		{"already a network address", "10.8.0.0/16", "10.8.0.0/16"},

		// Everything below must yield "" — no NAT cleanup — rather than a
		// subnet that matches more than this interface.
		{"empty", "", ""},
		{"garbage", "not-a-cidr", ""},
		{"bare IP, no mask", "10.0.0.1", ""},
		{"explicit v4 wildcard", "0.0.0.0/0", ""},
		{"v4 wildcard with host bits", "1.2.3.4/0", ""},
		{"explicit v6 wildcard", "::/0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := natSubnet(tt.address); got != tt.want {
				t.Fatalf("natSubnet(%q) = %q, want %q", tt.address, got, tt.want)
			}
		})
	}
}
