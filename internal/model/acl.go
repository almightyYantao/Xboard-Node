package model

// ACLConfig is the panel-pushed user access-control policy for this node.
//
// A nil *ACLConfig means the panel said nothing about ACL — the node then
// behaves exactly as it did before ACL existed. That is the compatibility
// contract with older panels and it is deliberately distinct from a pushed
// config whose Mode is "off": both disable enforcement, but only the latter
// tells us the panel knows about the feature. See docs-user-acl.md §3.4.
type ACLConfig struct {
	// Mode is "off", "dryrun", or "enforce". Empty is treated as "off".
	Mode string
	// DefaultAction is "allow" or "deny" — the verdict when no rule matches.
	DefaultAction string
	// ImplicitDNSAllow, when nil, defaults to true: under a deny default the
	// node keeps port 53 reachable so users can still resolve names. Without
	// it a default-deny node looks identical to a dead node.
	ImplicitDNSAllow *bool
	Groups           []ACLGroup
}

// ACLGroup is a named, ordered bundle of rules.
type ACLGroup struct {
	ID       string
	Priority int
	// DefaultAction overrides ACLConfig.DefaultAction for members of this
	// group. Empty means inherit.
	DefaultAction string
	Rules         []ACLRule
}

// ACLRule is one rule. Destination matchers (IPCIDRs, Domains,
// DomainSuffixes) form a single OR group; that group, Ports, and Protocols
// are ANDed. An empty group matches anything.
type ACLRule struct {
	// Action is "allow" or "deny".
	Action   string
	Priority int

	IPCIDRs        []string
	Domains        []string
	DomainSuffixes []string
	Ports          []string
	Protocols      []string
}

// DNSAllowed reports the effective implicit-DNS setting.
func (a *ACLConfig) DNSAllowed() bool {
	if a == nil || a.ImplicitDNSAllow == nil {
		return true
	}
	return *a.ImplicitDNSAllow
}
