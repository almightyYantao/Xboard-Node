package singbox

import (
	"testing"

	"github.com/sagernet/sing/common/domain"

	"github.com/cedar2025/xboard-node/internal/acl"
	"github.com/cedar2025/xboard-node/internal/model"
)

// Two independent suffix matchers decide the same question and must agree:
// sing-box's picks which domains get resolved (the acl_resolve_domains route
// rule), and the ACL's picks which domains a domain_suffixes rule covers. If
// they ever diverge, a domain would be resolved but not matched (or the other
// way round) and the policy would quietly mean something different from what
// the panel shows. Both are exercised here against the same table.
func TestSuffixMatchingAgreesWithSingBox(t *testing.T) {
	const suffix = "qunhequnhe.com"

	cases := []struct {
		host string
		want bool
	}{
		{"qunhequnhe.com", true},               // the apex itself
		{"a.qunhequnhe.com", true},             // one label
		{"kaptain.qunhequnhe.com", true},       // the real case
		{"x.x.qunhequnhe.com", true},           // several labels
		{"a.b.c.d.qunhequnhe.com", true},       // arbitrary depth
		{"evilqunhequnhe.com", false},          // no label boundary
		{"qunhequnhe.com.attacker.net", false}, // suffix in the middle
		{"com", false},
		{"other.com", false},
	}

	// Layer 1: sing-box's own matcher, built exactly as a route rule builds it
	// (NewDomainItem passes generateLegacy=false, which is what makes a bare
	// entry label-aware and inclusive of the apex).
	sbMatcher := domain.NewMatcher(nil, []string{suffix}, false)

	// Layer 2: the ACL's matcher, reached through a compiled policy.
	store := acl.New()
	if err := store.Update(&model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "deny",
		Groups: []model.ACLGroup{{
			ID:    "g",
			Rules: []model.ACLRule{{Action: "allow", DomainSuffixes: []string{suffix}}},
		}},
	}, []model.UserSpec{{ID: 1, UUID: "u", ACLGroups: []string{"g"}}}); err != nil {
		t.Fatalf("acl update: %v", err)
	}
	policy := store.Lookup("u")

	for _, tc := range cases {
		if got := sbMatcher.Match(tc.host); got != tc.want {
			t.Errorf("sing-box matcher: %q = %v, want %v", tc.host, got, tc.want)
		}
		got := policy.Check(acl.Dest{Domain: tc.host, Port: 443}) == acl.ActionAllow
		if got != tc.want {
			t.Errorf("acl matcher: %q = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// A leading dot means "subdomains only" to sing-box — it excludes the apex.
// normalizeResolveDomains strips it precisely to avoid that hole, so pin the
// behaviour that makes the stripping the right call.
func TestLeadingDotExcludesApex(t *testing.T) {
	withDot := domain.NewMatcher(nil, []string{".qunhequnhe.com"}, false)
	if withDot.Match("qunhequnhe.com") {
		t.Error(".suffix matched the apex; the stripping in normalizeResolveDomains is no longer needed")
	}
	if !withDot.Match("a.qunhequnhe.com") {
		t.Error(".suffix must still match subdomains")
	}
}
