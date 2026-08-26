package acl

import (
	"net/netip"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func users(specs ...model.UserSpec) []model.UserSpec { return specs }

func user(id int, uuid string, groups ...string) model.UserSpec {
	return model.UserSpec{ID: id, UUID: uuid, ACLGroups: groups}
}

func mustUpdate(t *testing.T, s *Store, cfg *model.ACLConfig, us []model.UserSpec) {
	t.Helper()
	if err := s.Update(cfg, us); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// ─── backward compatibility ─────────────────────────────────────────────

// A panel that never mentions ACL must leave the node exactly as it was.
func TestNilConfigEnforcesNothing(t *testing.T) {
	s := New()
	mustUpdate(t, s, nil, users(user(1, "uuid-1", "vip")))

	if s.Enabled() {
		t.Error("nil config must leave ACL disabled")
	}
	for _, identity := range []string{"uuid-1", "user@1", "unknown"} {
		if p := s.Lookup(identity); p != nil {
			t.Errorf("Lookup(%q) = %v, want nil", identity, p)
		}
	}
}

// A brand-new Store (no panel data yet) must not block anything either.
func TestZeroStoreAllowsEverything(t *testing.T) {
	s := New()
	if s.Enabled() {
		t.Error("fresh store must be disabled")
	}
	if got := s.Lookup("uuid-1").Check(Dest{IP: ip("10.0.0.1"), Port: 80}); got != ActionAllow {
		t.Errorf("Check = %v, want allow", got)
	}
}

func TestModeOffIgnoresRules(t *testing.T) {
	s := New()
	cfg := &model.ACLConfig{
		Mode:          "off",
		DefaultAction: "deny",
		Groups: []model.ACLGroup{{
			ID:    "vip",
			Rules: []model.ACLRule{{Action: "deny", IPCIDRs: []string{"0.0.0.0/0"}}},
		}},
	}
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "vip")))

	if s.Mode() != ModeOff {
		t.Fatalf("Mode = %v, want off", s.Mode())
	}
	if p := s.Lookup("uuid-1"); p != nil {
		t.Error("mode=off must return a nil policy")
	}
}

// ─── core semantics ─────────────────────────────────────────────────────

func denyByDefault(groups ...model.ACLGroup) *model.ACLConfig {
	return &model.ACLConfig{Mode: "enforce", DefaultAction: "deny", Groups: groups}
}

func TestDefaultDenyWithAllowList(t *testing.T) {
	cfg := denyByDefault(model.ACLGroup{
		ID: "vip",
		Rules: []model.ACLRule{{
			Action:  "allow",
			IPCIDRs: []string{"10.1.0.0/16", "203.0.113.0/24"},
		}},
	})
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "vip")))

	p := s.Lookup("uuid-1")
	cases := []struct {
		dest Dest
		want Action
	}{
		{Dest{IP: ip("10.1.2.3"), Port: 443}, ActionAllow},
		{Dest{IP: ip("203.0.113.9"), Port: 443}, ActionAllow},
		{Dest{IP: ip("10.2.0.1"), Port: 443}, ActionDeny},
		{Dest{IP: ip("8.8.8.8"), Port: 443}, ActionDeny},
	}
	for _, tc := range cases {
		if got := p.Check(tc.dest); got != tc.want {
			t.Errorf("Check(%v) = %v, want %v", tc.dest, got, tc.want)
		}
	}
}

// Destination matchers are one OR group; ports and protocols AND with it.
// A rule listing both a CIDR and a suffix must match either kind of target —
// ANDing across kinds would make such a rule unmatchable, since a
// destination is never an address and a hostname at once.
func TestDestinationMatchersAreORedPortsAreANDed(t *testing.T) {
	cfg := denyByDefault(model.ACLGroup{
		ID: "vip",
		Rules: []model.ACLRule{{
			Action:         "allow",
			IPCIDRs:        []string{"10.1.0.0/16"},
			DomainSuffixes: []string{"corp.example.com"},
			Ports:          []string{"443"},
		}},
	})
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "vip")))
	p := s.Lookup("uuid-1")

	cases := []struct {
		name string
		dest Dest
		want Action
	}{
		{"ip on allowed port", Dest{IP: ip("10.1.2.3"), Port: 443}, ActionAllow},
		{"domain on allowed port", Dest{Domain: "a.corp.example.com", Port: 443}, ActionAllow},
		{"ip on other port", Dest{IP: ip("10.1.2.3"), Port: 8080}, ActionDeny},
		{"domain on other port", Dest{Domain: "a.corp.example.com", Port: 8080}, ActionDeny},
		{"other ip on allowed port", Dest{IP: ip("8.8.8.8"), Port: 443}, ActionDeny},
	}
	for _, tc := range cases {
		if got := p.Check(tc.dest); got != tc.want {
			t.Errorf("%s: Check = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSuffixMatchesOnLabelBoundary(t *testing.T) {
	cfg := denyByDefault(model.ACLGroup{
		ID: "vip",
		Rules: []model.ACLRule{{
			Action:         "allow",
			DomainSuffixes: []string{"corp.example.com"},
		}},
	})
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "vip")))
	p := s.Lookup("uuid-1")

	cases := map[string]Action{
		"corp.example.com":          ActionAllow,
		"a.corp.example.com":        ActionAllow,
		"a.b.corp.example.com":      ActionAllow,
		"notcorp.example.com":       ActionDeny,
		"example.com":               ActionDeny,
		"corp.example.com.evil.net": ActionDeny,
	}
	for host, want := range cases {
		if got := p.Check(Dest{Domain: host, Port: 443}); got != want {
			t.Errorf("Check(%q) = %v, want %v", host, got, want)
		}
	}
}

// An IP rule must never match a domain target: the node does not resolve
// names at match time, so a CIDR allowlist cannot cover hostname traffic.
func TestIPRuleDoesNotMatchDomainTarget(t *testing.T) {
	cfg := denyByDefault(model.ACLGroup{
		ID:    "vip",
		Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"0.0.0.0/1", "128.0.0.0/1"}}},
	})
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "vip")))

	p := s.Lookup("uuid-1")
	if got := p.Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionAllow {
		t.Errorf("IP target: got %v, want allow", got)
	}
	if got := p.Check(Dest{Domain: "example.com", Port: 443}); got != ActionDeny {
		t.Errorf("domain target: got %v, want deny", got)
	}
}

func TestPortRangesAndProtocols(t *testing.T) {
	cfg := denyByDefault(model.ACLGroup{
		ID: "vip",
		Rules: []model.ACLRule{{
			Action:    "allow",
			Ports:     []string{"443", "8000-9000"},
			Protocols: []string{"tcp"},
		}},
	})
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "vip")))
	p := s.Lookup("uuid-1")

	cases := []struct {
		dest Dest
		want Action
	}{
		{Dest{IP: ip("1.1.1.1"), Port: 443}, ActionAllow},
		{Dest{IP: ip("1.1.1.1"), Port: 8000}, ActionAllow},
		{Dest{IP: ip("1.1.1.1"), Port: 9000}, ActionAllow},
		{Dest{IP: ip("1.1.1.1"), Port: 8500}, ActionAllow},
		{Dest{IP: ip("1.1.1.1"), Port: 7999}, ActionDeny},
		{Dest{IP: ip("1.1.1.1"), Port: 9001}, ActionDeny},
		{Dest{IP: ip("1.1.1.1"), Port: 443, UDP: true}, ActionDeny}, // protocol excludes UDP
	}
	for _, tc := range cases {
		if got := p.Check(tc.dest); got != tc.want {
			t.Errorf("Check(port=%d udp=%v) = %v, want %v", tc.dest.Port, tc.dest.UDP, got, tc.want)
		}
	}
}

// First match wins, ordered by group priority then rule priority — no
// implicit "deny beats allow" override.
func TestFirstMatchWinsAcrossGroups(t *testing.T) {
	cfg := &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "allow",
		Groups: []model.ACLGroup{
			{
				ID:       "broad-deny",
				Priority: 20,
				Rules:    []model.ACLRule{{Action: "deny", IPCIDRs: []string{"10.0.0.0/8"}}},
			},
			{
				ID:       "narrow-allow",
				Priority: 10,
				Rules:    []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.1.0.0/16"}}},
			},
		},
	}
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "broad-deny", "narrow-allow")))
	p := s.Lookup("uuid-1")

	// narrow-allow has the lower priority number, so it is evaluated first.
	if got := p.Check(Dest{IP: ip("10.1.2.3"), Port: 443}); got != ActionAllow {
		t.Errorf("carve-out: got %v, want allow", got)
	}
	if got := p.Check(Dest{IP: ip("10.9.9.9"), Port: 443}); got != ActionDeny {
		t.Errorf("rest of 10/8: got %v, want deny", got)
	}
	if got := p.Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionAllow {
		t.Errorf("unmatched falls to node default: got %v, want allow", got)
	}
}

func TestRulePriorityWithinGroup(t *testing.T) {
	cfg := &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "allow",
		Groups: []model.ACLGroup{{
			ID: "g",
			Rules: []model.ACLRule{
				{Action: "deny", Priority: 20, IPCIDRs: []string{"10.0.0.0/8"}},
				{Action: "allow", Priority: 10, IPCIDRs: []string{"10.1.0.0/16"}},
			},
		}},
	}
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "g")))
	p := s.Lookup("uuid-1")

	if got := p.Check(Dest{IP: ip("10.1.0.5"), Port: 1}); got != ActionAllow {
		t.Errorf("lower priority number must win: got %v", got)
	}
	if got := p.Check(Dest{IP: ip("10.5.0.5"), Port: 1}); got != ActionDeny {
		t.Errorf("got %v, want deny", got)
	}
}

func TestGroupDefaultOverridesNodeDefault(t *testing.T) {
	cfg := &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "deny",
		Groups: []model.ACLGroup{{
			ID:            "open",
			DefaultAction: "allow",
			Rules:         []model.ACLRule{{Action: "deny", IPCIDRs: []string{"10.0.0.0/8"}}},
		}},
	}
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "member", "open"), user(2, "outsider")))

	if got := s.Lookup("member").Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionAllow {
		t.Errorf("group default should allow: got %v", got)
	}
	if got := s.Lookup("member").Check(Dest{IP: ip("10.0.0.1"), Port: 443}); got != ActionDeny {
		t.Errorf("group rule should still deny: got %v", got)
	}
	if got := s.Lookup("outsider").Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionDeny {
		t.Errorf("no group should fall to node default deny: got %v", got)
	}
}

// ─── DNS escape hatch ───────────────────────────────────────────────────

func TestImplicitDNSAllowUnderDenyDefault(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(), users(user(1, "uuid-1")))

	p := s.Lookup("uuid-1")
	if got := p.Check(Dest{IP: ip("8.8.8.8"), Port: 53, UDP: true}); got != ActionAllow {
		t.Errorf("DNS must survive default deny: got %v", got)
	}
	if got := p.Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionDeny {
		t.Errorf("non-DNS must still be denied: got %v", got)
	}
}

func TestImplicitDNSCanBeDisabled(t *testing.T) {
	off := false
	cfg := denyByDefault()
	cfg.ImplicitDNSAllow = &off

	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1")))
	if got := s.Lookup("uuid-1").Check(Dest{IP: ip("8.8.8.8"), Port: 53, UDP: true}); got != ActionDeny {
		t.Errorf("explicit opt-out must deny DNS: got %v", got)
	}
}

// Under an allow default there is nothing to escape, so no implicit rule.
func TestNoImplicitDNSRuleUnderAllowDefault(t *testing.T) {
	cfg := &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "allow",
		Groups: []model.ACLGroup{{
			ID:    "g",
			Rules: []model.ACLRule{{Action: "deny", Ports: []string{"53"}}},
		}},
	}
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "uuid-1", "g")))
	if got := s.Lookup("uuid-1").Check(Dest{IP: ip("8.8.8.8"), Port: 53, UDP: true}); got != ActionDeny {
		t.Errorf("an explicit DNS deny must not be shadowed: got %v", got)
	}
}

// ─── identity indexing ──────────────────────────────────────────────────

// Both kernels must reach the same policy with the identity they already
// hold: sing-box the UUID, xray the stats email.
func TestBothIdentityFormsResolve(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(model.ACLGroup{
		ID:    "vip",
		Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}},
	}), users(user(42, "uuid-42", "vip")))

	byUUID := s.Lookup("uuid-42")
	byEmail := s.Lookup("user@42")
	if byUUID == nil || byEmail == nil {
		t.Fatal("both identity forms must resolve")
	}
	if byUUID != byEmail {
		t.Error("both identity forms must share one policy object")
	}
}

// An identity the node has no record of must not outrank a known one.
func TestUnknownIdentityInheritsDenyFallback(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(), users(user(1, "uuid-1")))

	if got := s.Lookup("who-is-this").Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionDeny {
		t.Errorf("unknown identity under default deny: got %v, want deny", got)
	}
}

func TestUnknownIdentityUnrestrictedUnderAllowDefault(t *testing.T) {
	s := New()
	mustUpdate(t, s, &model.ACLConfig{Mode: "enforce", DefaultAction: "allow"}, users(user(1, "uuid-1")))
	if got := s.Lookup("who-is-this").Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionAllow {
		t.Errorf("got %v, want allow", got)
	}
}

// ─── interning ──────────────────────────────────────────────────────────

// Users sharing a group must share one policy object; group order in the
// user record must not create a second one.
func TestPoliciesAreInternedPerGroupCombination(t *testing.T) {
	cfg := denyByDefault(
		model.ACLGroup{ID: "a", Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}}},
		model.ACLGroup{ID: "b", Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"192.168.0.0/16"}}}},
	)
	s := New()
	mustUpdate(t, s, cfg, users(
		user(1, "u1", "a"),
		user(2, "u2", "a"),
		user(3, "u3", "a", "b"),
		user(4, "u4", "b", "a"), // same set, different order
	))

	if s.Lookup("u1") != s.Lookup("u2") {
		t.Error("same single group must share a policy")
	}
	if s.Lookup("u3") != s.Lookup("u4") {
		t.Error("group order must not produce a distinct policy")
	}
	if s.Lookup("u1") == s.Lookup("u3") {
		t.Error("different group sets must not share a policy")
	}
}

// Unrestricted users must all share the one allow-all object.
func TestUnrestrictedUsersShareAllowAll(t *testing.T) {
	s := New()
	mustUpdate(t, s, &model.ACLConfig{Mode: "enforce", DefaultAction: "allow"},
		users(user(1, "u1"), user(2, "u2")))

	p1, p2 := s.Lookup("u1"), s.Lookup("u2")
	if p1 != p2 {
		t.Error("unrestricted users must share one policy object")
	}
	if p1.Restricted() {
		t.Error("allow-all policy must report itself unrestricted")
	}
}

func TestUnknownGroupReferenceIsIgnored(t *testing.T) {
	cfg := denyByDefault(model.ACLGroup{
		ID:    "vip",
		Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}},
	})
	s := New()
	mustUpdate(t, s, cfg, users(user(1, "u1", "vip", "deleted-group")))

	// The dangling reference is dropped, the real group still applies.
	if got := s.Lookup("u1").Check(Dest{IP: ip("10.0.0.1"), Port: 443}); got != ActionAllow {
		t.Errorf("got %v, want allow", got)
	}
	if got := s.Lookup("u1").Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionDeny {
		t.Errorf("got %v, want deny", got)
	}
}

// ─── dry run ────────────────────────────────────────────────────────────

func TestDryRunStillEvaluatesButFlags(t *testing.T) {
	cfg := denyByDefault()
	cfg.Mode = "dryrun"

	s := New()
	mustUpdate(t, s, cfg, users(user(1, "u1")))

	p := s.Lookup("u1")
	if !p.DryRun() {
		t.Error("policy must report dry-run")
	}
	if got := p.Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionDeny {
		t.Errorf("dry-run must still compute the verdict: got %v", got)
	}
	if s.Mode() != ModeDryRun {
		t.Errorf("Mode = %v, want dryrun", s.Mode())
	}
}

// ─── failure handling ───────────────────────────────────────────────────

// A rejected push must leave the previous policy live. Falling back to "no
// policy" would open a node the operator believes is locked down.
func TestRejectedUpdateKeepsPreviousPolicy(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(), users(user(1, "u1")))

	bad := denyByDefault(model.ACLGroup{
		ID:    "vip",
		Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"not-a-cidr"}}},
	})
	if err := s.Update(bad, users(user(1, "u1", "vip"))); err == nil {
		t.Fatal("Update should have rejected an invalid CIDR")
	}

	if got := s.Lookup("u1").Check(Dest{IP: ip("8.8.8.8"), Port: 443}); got != ActionDeny {
		t.Errorf("previous deny policy must survive a rejected push: got %v", got)
	}
}

func TestEmptyUserListUnderDenyStillBlocksUnknowns(t *testing.T) {
	s := New()
	mustUpdate(t, s, denyByDefault(), nil)
	if got := s.Lookup("anyone").Check(Dest{IP: ip("1.1.1.1"), Port: 80}); got != ActionDeny {
		t.Errorf("got %v, want deny", got)
	}
}

// ─── benchmarks ─────────────────────────────────────────────────────────

func benchStore(userCount, groupCount, cidrsPerGroup int) (*Store, string) {
	groups := make([]model.ACLGroup, groupCount)
	for g := range groups {
		cidrs := make([]string, cidrsPerGroup)
		for i := range cidrs {
			v := (g*cidrsPerGroup + i) * 7
			cidrs[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{
				byte(11 + (v/65536)%200), byte((v / 256) % 256), byte(v % 256), 0,
			}), 24).String()
		}
		groups[g] = model.ACLGroup{
			ID:    "g" + itoa(g),
			Rules: []model.ACLRule{{Action: "allow", IPCIDRs: cidrs}},
		}
	}
	us := make([]model.UserSpec, userCount)
	for i := range us {
		us[i] = model.UserSpec{
			ID:        i + 1,
			UUID:      "uuid-" + itoa(i),
			ACLGroups: []string{"g" + itoa(i%groupCount)},
		}
	}
	s := New()
	if err := s.Update(&model.ACLConfig{Mode: "enforce", DefaultAction: "deny", Groups: groups}, us); err != nil {
		panic(err)
	}
	return s, "uuid-" + itoa(userCount/2)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func BenchmarkCheck(b *testing.B) {
	s, uuid := benchStore(5000, 100, 1000)
	dest := Dest{IP: ip("142.250.72.14"), Port: 443}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if s.Lookup(uuid).Check(dest) != ActionDeny {
			b.Fatal("unexpected verdict")
		}
	}
}

func BenchmarkCheckParallel(b *testing.B) {
	s, uuid := benchStore(5000, 100, 1000)
	dest := Dest{IP: ip("142.250.72.14"), Port: 443}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = s.Lookup(uuid).Check(dest)
		}
	})
}

func BenchmarkUpdate(b *testing.B) {
	groups := make([]model.ACLGroup, 100)
	for g := range groups {
		cidrs := make([]string, 1000)
		for i := range cidrs {
			v := (g*1000 + i) * 7
			cidrs[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{
				byte(11 + (v/65536)%200), byte((v / 256) % 256), byte(v % 256), 0,
			}), 24).String()
		}
		groups[g] = model.ACLGroup{ID: "g" + itoa(g),
			Rules: []model.ACLRule{{Action: "allow", IPCIDRs: cidrs}}}
	}
	us := make([]model.UserSpec, 5000)
	for i := range us {
		us[i] = model.UserSpec{ID: i + 1, UUID: "uuid-" + itoa(i),
			ACLGroups: []string{"g" + itoa(i%100)}}
	}
	cfg := &model.ACLConfig{Mode: "enforce", DefaultAction: "deny", Groups: groups}

	s := New()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Update(cfg, us); err != nil {
			b.Fatal(err)
		}
	}
}
