package acl

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

// Evaluate must name the rule that decided the outcome, so the panel can show
// which rule blocked (or would block) a connection.
func TestEvaluateReportsMatchedRule(t *testing.T) {
	cfg := &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "allow",
		Groups: []model.ACLGroup{{
			ID: "vip",
			Rules: []model.ACLRule{
				{Action: "allow", Priority: 10, IPCIDRs: []string{"10.1.0.0/16"}},
				{Action: "deny", Priority: 20, IPCIDRs: []string{"10.0.0.0/8"}},
			},
		}},
	}
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "u1", "vip")))
	p := s.Lookup("u1")

	// Origins carry the group id and the rule's index in the pushed array,
	// not its position after priority sorting — so an operator can find the
	// rule in the panel.
	cases := []struct {
		dest       Dest
		wantAction Action
		wantOrigin string
	}{
		{Dest{IP: ip("10.1.0.5"), Port: 443}, ActionAllow, "vip#0"},
		{Dest{IP: ip("10.9.0.5"), Port: 443}, ActionDeny, "vip#1"},
		{Dest{IP: ip("8.8.8.8"), Port: 443}, ActionAllow, OriginDefault},
	}
	for _, tc := range cases {
		action, origin := p.Evaluate(tc.dest)
		if action != tc.wantAction || origin != tc.wantOrigin {
			t.Errorf("Evaluate(%v) = %v/%q, want %v/%q",
				tc.dest, action, origin, tc.wantAction, tc.wantOrigin)
		}
	}
}

func TestEvaluateNilPolicy(t *testing.T) {
	var p *Policy
	action, origin := p.Evaluate(Dest{IP: ip("1.1.1.1"), Port: 80})
	if action != ActionAllow || origin != OriginDefault {
		t.Errorf("nil policy: got %v/%q", action, origin)
	}
}

// The implicit DNS rule must be identifiable in reports, so an operator
// seeing DNS traffic pass under a deny default knows why.
func TestEvaluateNamesImplicitDNSRule(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(), users(user(1, "u1")))

	action, origin := s.Lookup("u1").Evaluate(Dest{IP: ip("8.8.8.8"), Port: 53, UDP: true})
	if action != ActionAllow || origin != "implicit-dns" {
		t.Errorf("got %v/%q, want allow/implicit-dns", action, origin)
	}
}

func TestModeLabel(t *testing.T) {
	dry := denyByDefault()
	dry.Mode = "dryrun"
	sd := New()
	mustUpdate(t, sd, dry, users(user(1, "u1")))
	if got := sd.Lookup("u1").ModeLabel(); got != "dryrun" {
		t.Errorf("ModeLabel = %q, want dryrun", got)
	}

	se := New()
	mustUpdate(t, se, denyByDefault(), users(user(1, "u1")))
	if got := se.Lookup("u1").ModeLabel(); got != "enforce" {
		t.Errorf("ModeLabel = %q, want enforce", got)
	}
}

// Check must stay allocation-free now that it delegates to Evaluate.
func BenchmarkEvaluate(b *testing.B) {
	s, uuid := benchStore(5000, 100, 1000)
	dest := Dest{IP: ip("142.250.72.14"), Port: 443}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, origin := s.Lookup(uuid).Evaluate(dest); origin == "" {
			b.Fatal("empty origin")
		}
	}
}

// The match_resolved path costs one IPSet lookup per resolved address inside
// the first pass, where the plain path costs none. Pinned next to the others
// so a regression here shows up as a number, not as a hunch.
func BenchmarkEvaluateMatchResolved(b *testing.B) {
	s := New()
	if err := s.Update(&model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "allow",
		Groups: []model.ACLGroup{{
			ID: "corp",
			Rules: []model.ACLRule{
				{Action: "allow", Priority: 10, IPCIDRs: []string{"10.0.0.1/32"}, MatchResolved: true},
				{Action: "deny", Priority: 100, IPCIDRs: []string{"10.0.0.0/8"}},
				{Action: "deny", Priority: 110, DomainSuffixes: []string{"corp.example.com"}},
			},
		}},
	}, users(user(1, "u1", "corp"))); err != nil {
		b.Fatal(err)
	}
	dest := Dest{Domain: "a.corp.example.com", Port: 443, ResolvedIPs: ips("10.0.0.1")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, origin := s.Lookup("u1").Evaluate(dest); origin == "" {
			b.Fatal("empty origin")
		}
	}
}
