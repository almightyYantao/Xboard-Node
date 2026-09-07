package model

import "testing"

func allowRule(r ACLRule) *ACLConfig {
	return &ACLConfig{
		Mode:          "enforce",
		DefaultAction: "deny",
		Groups:        []ACLGroup{{ID: "g", Rules: []ACLRule{r}}},
	}
}

func TestValidateACLConfigNilIsValid(t *testing.T) {
	if err := ValidateACLConfig(nil); err != nil {
		t.Errorf("nil config must validate: %v", err)
	}
}

func TestValidateACLConfigAccepts(t *testing.T) {
	cfg := &ACLConfig{
		Mode:          "enforce",
		DefaultAction: "deny",
		Groups: []ACLGroup{{
			ID:            "vip",
			Priority:      10,
			DefaultAction: "allow",
			Rules: []ACLRule{{
				Action:         "allow",
				IPCIDRs:        []string{"10.1.0.0/16", "2001:db8::/32"},
				DomainSuffixes: []string{"corp.example.com"},
				Ports:          []string{"443", "8000-9000"},
				Protocols:      []string{"tcp", "udp"},
			}},
		}},
	}
	if err := ValidateACLConfig(cfg); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// A CIDR with host bits set is normalised rather than rejected, matching
// what net.ParseCIDR does everywhere else in the node.
func TestValidateACLConfigAcceptsUnmaskedCIDR(t *testing.T) {
	if err := ValidateACLConfig(allowRule(ACLRule{
		Action: "allow", IPCIDRs: []string{"10.0.0.1/8"},
	})); err != nil {
		t.Errorf("host bits should be masked, not rejected: %v", err)
	}
}

// Broad prefixes are a deliberate allow-everything, not an attempt to reach
// loopback. The panel warns; the node accepts.
func TestValidateACLConfigAcceptsBroadPrefixes(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "::/0"} {
		if err := ValidateACLConfig(allowRule(ACLRule{
			Action: "allow", IPCIDRs: []string{cidr},
		})); err != nil {
			t.Errorf("%s should be accepted: %v", cidr, err)
		}
	}
}

func TestValidateACLConfigRejectsForbiddenAllowTargets(t *testing.T) {
	for _, cidr := range []string{
		"127.0.0.0/8",
		"127.0.0.1/32",
		"169.254.0.0/16",
		"169.254.169.254/32",
		"0.0.0.0/32",
		"::1/128",
		"fe80::/10",
	} {
		err := ValidateACLConfig(allowRule(ACLRule{Action: "allow", IPCIDRs: []string{cidr}}))
		if err == nil {
			t.Errorf("allowing %s must be rejected", cidr)
		}
	}
}

// The same ranges are fine in a deny rule — denying loopback is harmless.
func TestValidateACLConfigAllowsForbiddenTargetsInDenyRule(t *testing.T) {
	if err := ValidateACLConfig(allowRule(ACLRule{
		Action: "deny", IPCIDRs: []string{"127.0.0.0/8"},
	})); err != nil {
		t.Errorf("denying loopback should be fine: %v", err)
	}
}

func TestValidateACLConfigRejects(t *testing.T) {
	cases := []struct {
		name string
		cfg  *ACLConfig
	}{
		{"bad mode", &ACLConfig{Mode: "on", DefaultAction: "deny"}},
		{"bad default action", &ACLConfig{Mode: "enforce", DefaultAction: "drop"}},
		{"bad group id", &ACLConfig{Mode: "enforce", DefaultAction: "deny",
			Groups: []ACLGroup{{ID: "Not Valid!", Rules: []ACLRule{{Action: "deny", Ports: []string{"1"}}}}}}},
		{"duplicate group id", &ACLConfig{Mode: "enforce", DefaultAction: "deny",
			Groups: []ACLGroup{
				{ID: "g", Rules: []ACLRule{{Action: "deny", Ports: []string{"1"}}}},
				{ID: "g", Rules: []ACLRule{{Action: "deny", Ports: []string{"2"}}}},
			}}},
		{"bad action", allowRule(ACLRule{Action: "drop", Ports: []string{"443"}})},
		{"missing action", allowRule(ACLRule{Ports: []string{"443"}})},
		{"no match condition", allowRule(ACLRule{Action: "deny"})},
		{"bad cidr", allowRule(ACLRule{Action: "allow", IPCIDRs: []string{"10.0.0/8"}})},
		{"bare ip as cidr", allowRule(ACLRule{Action: "allow", IPCIDRs: []string{"10.0.0.1"}})},
		{"port zero", allowRule(ACLRule{Action: "allow", Ports: []string{"0"}})},
		{"port too high", allowRule(ACLRule{Action: "allow", Ports: []string{"70000"}})},
		{"inverted port range", allowRule(ACLRule{Action: "allow", Ports: []string{"9000-8000"}})},
		{"bad protocol", allowRule(ACLRule{Action: "allow", Protocols: []string{"icmp"}})},
		{"domain with scheme", allowRule(ACLRule{Action: "allow", Domains: []string{"https://a.com"}})},
		{"domain with path", allowRule(ACLRule{Action: "allow", Domains: []string{"a.com/x"}})},
		{"leading dot suffix", allowRule(ACLRule{Action: "allow", DomainSuffixes: []string{".a.com"}})},
	}
	for _, tc := range cases {
		if err := ValidateACLConfig(tc.cfg); err == nil {
			t.Errorf("%s: expected rejection", tc.name)
		}
	}
}

func TestValidateACLConfigRejectsOversizedGroup(t *testing.T) {
	cidrs := make([]string, maxACLCIDRsPerGroup+1)
	for i := range cidrs {
		cidrs[i] = "10.0.0.0/8"
	}
	if err := ValidateACLConfig(allowRule(ACLRule{Action: "allow", IPCIDRs: cidrs})); err == nil {
		t.Error("expected the per-group CIDR limit to be enforced")
	}
}

func TestACLDNSAllowedDefaultsTrue(t *testing.T) {
	var nilCfg *ACLConfig
	if !nilCfg.DNSAllowed() {
		t.Error("nil config must report DNS allowed")
	}
	if !(&ACLConfig{}).DNSAllowed() {
		t.Error("omitted implicit_dns_allow must default to true")
	}
	off := false
	if (&ACLConfig{ImplicitDNSAllow: &off}).DNSAllowed() {
		t.Error("explicit false must be honoured")
	}
}

// match_resolved only extends ip_cidrs, so on a rule without any it is a
// silently ineffective flag. Refuse it for the same reason a rule with no
// matcher at all is refused.
func TestValidateACLConfigRejectsMatchResolvedWithoutCIDRs(t *testing.T) {
	cfg := allowRule(ACLRule{
		Action:         "allow",
		DomainSuffixes: []string{"corp.example.com"},
		MatchResolved:  true,
	})
	if err := ValidateACLConfig(cfg); err == nil {
		t.Error("match_resolved without ip_cidrs must be rejected")
	}
}

func TestValidateACLConfigAcceptsMatchResolvedWithCIDRs(t *testing.T) {
	cfg := allowRule(ACLRule{
		Action:        "allow",
		IPCIDRs:       []string{"10.0.0.1/32"},
		MatchResolved: true,
	})
	if err := ValidateACLConfig(cfg); err != nil {
		t.Errorf("valid match_resolved rule rejected: %v", err)
	}
}
