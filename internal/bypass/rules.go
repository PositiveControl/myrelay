package bypass

import (
	"strings"

	"github.com/m7s/vpn/internal/models"
	"github.com/m7s/vpn/internal/wireguard"
)

// Rule is a named group of CIDRs to bypass (route outside the tunnel).
type Rule struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// Registry of all available bypass rules.
var Rules = map[string]Rule{
	"apple": {
		Name:  "apple",
		CIDRs: []string{"17.0.0.0/8"},
	},
	"netflix": {
		Name:  "netflix",
		CIDRs: []string{"23.246.0.0/18", "45.57.0.0/17", "64.120.128.0/17", "66.197.128.0/17", "108.175.32.0/20", "185.2.220.0/22", "185.9.188.0/22", "192.173.64.0/18", "198.38.96.0/19", "198.45.48.0/20"},
	},
	"spotify": {
		Name:  "spotify",
		CIDRs: []string{"35.186.224.0/20", "78.31.8.0/22", "104.154.0.0/15", "104.199.64.0/18", "193.182.8.0/22", "194.132.196.0/22"},
	},
	"youtube": {
		Name:  "youtube",
		CIDRs: []string{"208.65.152.0/22", "208.117.224.0/19", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19"},
	},
}

// PlanDefaults maps plans to the default bypass rule names.
var PlanDefaults = map[models.Plan][]string{
	models.PlanStandard: {"apple", "netflix", "spotify", "youtube"},
	models.PlanPremium:  {},
}

// ListRules returns all available rules sorted by name.
func ListRules() []Rule {
	rules := make([]Rule, 0, len(Rules))
	for _, r := range Rules {
		rules = append(rules, r)
	}
	return rules
}

// ResolveRuleNames returns the effective rule names for a user given their plan
// and optional override. If override is nil, plan defaults are used. If override
// is non-nil (including empty string), it completely replaces plan defaults.
func ResolveRuleNames(plan models.Plan, override *string) []string {
	if override != nil {
		if *override == "" {
			return nil // force full tunnel
		}
		return strings.Split(*override, ",")
	}
	defaults, ok := PlanDefaults[plan]
	if !ok {
		return nil
	}
	return defaults
}

// CollectCIDRs gathers all CIDRs for the given rule names.
func CollectCIDRs(ruleNames []string) []string {
	var cidrs []string
	for _, name := range ruleNames {
		if rule, ok := Rules[strings.TrimSpace(name)]; ok {
			cidrs = append(cidrs, rule.CIDRs...)
		}
	}
	return cidrs
}

// ComputeAllowedIPsForUser resolves bypass rules for a user and computes the
// AllowedIPs string for their WireGuard config.
func ComputeAllowedIPsForUser(plan models.Plan, override *string) (string, error) {
	ruleNames := ResolveRuleNames(plan, override)
	cidrs := CollectCIDRs(ruleNames)
	return wireguard.ComputeAllowedIPs(cidrs)
}
