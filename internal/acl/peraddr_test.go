package acl

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

// The production policy that motivated per-address judging: the operator
// allows internal segments by CIDR, resolves the corp zone on the node, and
// sso-gateway.qunhequnhe.com answers with its internal AND its public address.
// Judging the answer as a whole denied the name (the /16 allow could not cover
// the public address, the 10/8 deny caught the internal one).
func ipOnlyPolicy(t *testing.T, extra ...model.ACLRule) *Policy {
	t.Helper()
	rules := append([]model.ACLRule{}, extra...)
	rules = append(rules,
		model.ACLRule{Action: "allow", Priority: 40, IPCIDRs: []string{"10.101.0.0/16"}, MatchResolved: true},
		model.ACLRule{Action: "deny", Priority: 100, IPCIDRs: []string{"10.0.0.0/8"}, MatchResolved: true},
		model.ACLRule{Action: "deny", Priority: 200, DomainSuffixes: []string{"qunhequnhe.com"}},
	)
	s := New()
	mustUpdate(t, s, denyByDefault(model.ACLGroup{ID: "base", Rules: rules}),
		users(user(1, "u1", "base")))
	return s.Lookup("u1")
}

func TestPerAddressMixedAnswerDialsOnlyAllowed(t *testing.T) {
	p := ipOnlyPolicy(t)
	d := p.Decide(Dest{
		Domain:      "sso-gateway.qunhequnhe.com",
		Port:        443,
		ResolvedIPs: ips("183.129.228.249", "10.101.30.4"),
	})
	if d.Action != ActionAllow || d.Origin != "base#0" {
		t.Fatalf("got %v/%q, want allow/base#0", d.Action, d.Origin)
	}
	if want := ips("10.101.30.4"); !slices.Equal(d.DialOnly, want) {
		t.Errorf("DialOnly = %v, want %v", d.DialOnly, want)
	}
}

func TestPerAddressNothingAllowedDenies(t *testing.T) {
	p := ipOnlyPolicy(t)
	cases := []struct {
		name, origin string
		addrs        []netip.Addr
	}{
		// Public-only answer: no rule allows it, the suffix deny names it.
		{"www.qunhequnhe.com", "base#2", ips("1.2.3.4")},
		// Unauthorised internal segment: the 10/8 deny.
		{"git.qunhequnhe.com", "base#1", ips("10.20.0.5")},
		// Outside the zone and public-only: the default.
		{"www.example.com", OriginDefault, ips("1.2.3.4")},
	}
	for _, c := range cases {
		d := p.Decide(Dest{Domain: c.name, Port: 443, ResolvedIPs: c.addrs})
		if d.Action != ActionDeny || d.Origin != c.origin || d.DialOnly != nil {
			t.Errorf("%s: got %v/%q dial=%v, want deny/%q", c.name, d.Action, d.Origin, d.DialOnly, c.origin)
		}
	}
}

// An operator who wants public answers reachable says so with an ordinary IP
// rule after the internal deny; per-address judging then keeps both addresses
// and the kernel tries the internal one first.
func TestPerAddressPublicAllowKeepsBothInternalFirst(t *testing.T) {
	p := ipOnlyPolicy(t, model.ACLRule{Action: "allow", Priority: 150, IPCIDRs: []string{"0.0.0.0/0"}, MatchResolved: true})
	d := p.Decide(Dest{
		Domain:      "sso-gateway.qunhequnhe.com",
		Port:        443,
		ResolvedIPs: ips("183.129.228.249", "10.101.30.4"),
	})
	if d.Action != ActionAllow {
		t.Fatalf("got %v, want allow", d.Action)
	}
	if want := ips("10.101.30.4", "183.129.228.249"); !slices.Equal(d.DialOnly, want) {
		t.Errorf("DialOnly = %v, want %v", d.DialOnly, want)
	}
	// Public-only names now pass too, and need no reordering.
	d = p.Decide(Dest{Domain: "www.qunhequnhe.com", Port: 443, ResolvedIPs: ips("1.2.3.4")})
	if d.Action != ActionAllow || d.DialOnly != nil {
		t.Errorf("public-only: got %v dial=%v, want allow without constraint", d.Action, d.DialOnly)
	}
	// The internal deny still holds for an unauthorised segment.
	d = p.Decide(Dest{Domain: "git.qunhequnhe.com", Port: 443, ResolvedIPs: ips("10.20.0.5")})
	if d.Action != ActionDeny {
		t.Errorf("unauthorised internal: got %v, want deny", d.Action)
	}
}

// Already all-allowed and internal-first: no constraint, so the hot path does
// not allocate and the outbound does not touch the addresses.
func TestPerAddressNoConstraintWhenNothingToChange(t *testing.T) {
	p := ipOnlyPolicy(t)
	d := p.Decide(Dest{Domain: "a.qunhequnhe.com", Port: 443, ResolvedIPs: ips("10.101.1.1", "10.101.1.2")})
	if d.Action != ActionAllow || d.DialOnly != nil {
		t.Errorf("got %v dial=%v, want allow without constraint", d.Action, d.DialOnly)
	}
}

func TestIsPublic(t *testing.T) {
	cases := map[string]bool{
		"183.129.228.249": true,
		"8.8.8.8":         true,
		"2400:3200::1":    true,
		"::ffff:1.1.1.1":  true,
		"10.1.2.3":        false,
		"172.20.0.1":      false,
		"192.168.1.1":     false,
		"100.100.1.1":     false,
		"127.0.0.1":       false,
		"169.254.169.254": false,
		"198.18.0.1":      false,
		"224.0.0.1":       false,
		"::ffff:10.0.0.1": false,
		"fd00::1":         false,
		"fe80::1":         false,
		"64:ff9b::a00:1":  false,
		"::1":             false,
	}
	for raw, want := range cases {
		if got := IsPublic(netip.MustParseAddr(raw)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", raw, got, want)
		}
	}
}
