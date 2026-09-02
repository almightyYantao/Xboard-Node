package acl

import (
	"net/netip"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func ips(list ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// The case this whole mechanism exists for: an operator writes an ip_cidr
// allowlist for an internal segment, but clients address that segment by
// hostname. Without ResolvedIPs the CIDR rule can never match and every such
// connection falls to the deny default.
func TestResolvedIPsSatisfyCIDRAllowlist(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(model.ACLGroup{
		ID:    "internal",
		Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}},
	}), users(user(1, "u1", "internal")))
	p := s.Lookup("u1")

	dest := Dest{
		Domain:      "kaptain.example.com",
		Port:        443,
		ResolvedIPs: ips("10.101.30.24"),
	}
	if action, origin := p.Evaluate(dest); action != ActionAllow || origin != "internal#0" {
		t.Errorf("with resolution: got %v/%q, want allow/internal#0", action, origin)
	}

	// The same connection with nothing resolved must behave exactly as it did
	// before this change: the name matches no rule, so the default decides.
	bare := dest
	bare.ResolvedIPs = nil
	if action, origin := p.Evaluate(bare); action != ActionDeny || origin != OriginDefault {
		t.Errorf("without resolution: got %v/%q, want deny/default", action, origin)
	}
}

// One forbidden address among several denies the connection: the kernel may
// dial any of them, so an allowlist that passed on "at least one is permitted"
// would be trivially bypassable with a mixed DNS answer.
func TestResolvedIPsAnyDenyWins(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(model.ACLGroup{
		ID:    "internal",
		Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}},
	}), users(user(1, "u1", "internal")))
	p := s.Lookup("u1")

	dest := Dest{
		Domain:      "mixed.example.com",
		Port:        443,
		ResolvedIPs: ips("10.1.0.5", "203.0.113.9"),
	}
	if action, origin := p.Evaluate(dest); action != ActionDeny || origin != OriginDefault {
		t.Errorf("mixed answer: got %v/%q, want deny/default", action, origin)
	}
}

// The same asymmetry has to work for a blocklist on an allow-default node:
// a forbidden address hiding behind permitted ones must still be caught.
func TestResolvedIPsCatchBlocklistUnderAllowDefault(t *testing.T) {
	cfg := &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "allow",
		Groups: []model.ACLGroup{{
			ID:    "guard",
			Rules: []model.ACLRule{{Action: "deny", IPCIDRs: []string{"10.0.0.0/8"}}},
		}},
	}
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "u1", "guard")))
	p := s.Lookup("u1")

	dest := Dest{
		Domain:      "sneaky.example.com",
		Port:        443,
		ResolvedIPs: ips("1.1.1.1", "10.9.0.5"),
	}
	if action, origin := p.Evaluate(dest); action != ActionDeny || origin != "guard#0" {
		t.Errorf("blocklist: got %v/%q, want deny/guard#0", action, origin)
	}
}

// A rule naming the domain is the operator stating their intent about that
// name, so it decides the outcome and the resolved addresses never get a turn
// — in both directions.
func TestDomainRuleOutranksResolvedIPs(t *testing.T) {
	cfg := &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "deny",
		Groups: []model.ACLGroup{{
			ID: "mix",
			Rules: []model.ACLRule{
				{Action: "allow", Priority: 10, DomainSuffixes: []string{"ok.example.com"}},
				{Action: "deny", Priority: 20, DomainSuffixes: []string{"no.example.com"}},
				{Action: "allow", Priority: 30, IPCIDRs: []string{"10.0.0.0/8"}},
			},
		}},
	}
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "u1", "mix")))
	p := s.Lookup("u1")

	// Domain allow wins even though the resolved address is outside the CIDR.
	allowed := Dest{Domain: "a.ok.example.com", Port: 443, ResolvedIPs: ips("203.0.113.9")}
	if action, origin := p.Evaluate(allowed); action != ActionAllow || origin != "mix#0" {
		t.Errorf("domain allow: got %v/%q, want allow/mix#0", action, origin)
	}

	// Domain deny wins even though the resolved address is inside the CIDR.
	denied := Dest{Domain: "b.no.example.com", Port: 443, ResolvedIPs: ips("10.1.0.5")}
	if action, origin := p.Evaluate(denied); action != ActionDeny || origin != "mix#1" {
		t.Errorf("domain deny: got %v/%q, want deny/mix#1", action, origin)
	}
}

// An IP-addressed connection is judged on the address the kernel will actually
// dial, never on a resolution list that happens to accompany it.
func TestResolvedIPsIgnoredForIPTargets(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(model.ACLGroup{
		ID:    "internal",
		Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}},
	}), users(user(1, "u1", "internal")))
	p := s.Lookup("u1")

	dest := Dest{IP: ip("203.0.113.9"), Port: 443, ResolvedIPs: ips("10.1.0.5")}
	if action, origin := p.Evaluate(dest); action != ActionDeny || origin != OriginDefault {
		t.Errorf("ip target: got %v/%q, want deny/default", action, origin)
	}
}

// Port and protocol conditions still AND with the destination after the
// fallback: the resolved address must satisfy the whole rule, not just its
// CIDR half.
func TestResolvedIPsRespectPortCondition(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(model.ACLGroup{
		ID: "internal",
		Rules: []model.ACLRule{{
			Action:  "allow",
			IPCIDRs: []string{"10.0.0.0/8"},
			Ports:   []string{"443"},
		}},
	}), users(user(1, "u1", "internal")))
	p := s.Lookup("u1")

	ok := Dest{Domain: "svc.example.com", Port: 443, ResolvedIPs: ips("10.1.0.5")}
	if action, _ := p.Evaluate(ok); action != ActionAllow {
		t.Errorf("port 443: got %v, want allow", action)
	}
	bad := Dest{Domain: "svc.example.com", Port: 80, ResolvedIPs: ips("10.1.0.5")}
	if action, _ := p.Evaluate(bad); action != ActionDeny {
		t.Errorf("port 80: got %v, want deny", action)
	}
}

// IPv4-in-IPv6 addresses are what a dual-stack resolver hands back; they must
// match a v4 CIDR rule rather than silently missing it.
func TestResolvedIPsUnmapV4In6(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(model.ACLGroup{
		ID:    "internal",
		Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}},
	}), users(user(1, "u1", "internal")))
	p := s.Lookup("u1")

	dest := Dest{
		Domain:      "svc.example.com",
		Port:        443,
		ResolvedIPs: []netip.Addr{netip.MustParseAddr("::ffff:10.1.0.5")},
	}
	if action, origin := p.Evaluate(dest); action != ActionAllow || origin != "internal#0" {
		t.Errorf("v4-in-v6: got %v/%q, want allow/internal#0", action, origin)
	}
}

// The implicit DNS allowance still fires before any resolution fallback, so a
// default-deny node keeps name resolution working.
func TestImplicitDNSUnaffectedByResolution(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(), users(user(1, "u1")))

	dest := Dest{Domain: "resolver.example.com", Port: 53, UDP: true, ResolvedIPs: ips("203.0.113.9")}
	if action, origin := s.Lookup("u1").Evaluate(dest); action != ActionAllow || origin != "implicit-dns" {
		t.Errorf("got %v/%q, want allow/implicit-dns", action, origin)
	}
}

// The fallback must stay off the hot path for the overwhelming majority of
// connections, which carry no resolution list at all.
func BenchmarkEvaluateResolved(b *testing.B) {
	s, uuid := benchStore(5000, 100, 1000)
	dest := Dest{
		Domain:      "example.com",
		Port:        443,
		ResolvedIPs: ips("142.250.72.14", "142.250.72.15"),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, origin := s.Lookup(uuid).Evaluate(dest); origin == "" {
			b.Fatal("empty origin")
		}
	}
}
