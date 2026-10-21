package singbox

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	singM "github.com/sagernet/sing/common/metadata"

	"github.com/cedar2025/xboard-node/internal/acl"
	"github.com/cedar2025/xboard-node/internal/model"
)

// A `resolve` route action leaves InboundContext.Destination as the FQDN and
// only fills DestinationAddresses. This test pins that wiring: it is the half
// of the feature the acl package cannot see, and getting it wrong is silent —
// the ACL simply keeps judging the name and denying on the default.
func TestACLSeesResolvedAddresses(t *testing.T) {
	store := acl.New()
	cfg := &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "deny",
		Groups: []model.ACLGroup{{
			ID:    "internal",
			Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}},
		}},
	}
	const uuid = "28d860d7-ff89-4dc5-bb21-930627bcb0a7"
	if err := store.Update(cfg, []model.UserSpec{{ID: 42, UUID: uuid, ACLGroups: []string{"internal"}}}); err != nil {
		t.Fatalf("acl update: %v", err)
	}

	tr := NewConnTracker(0)
	tr.SetACLFunc(store.Lookup)

	meta := func(addrs ...string) adapter.InboundContext {
		m := adapter.InboundContext{
			Destination: singM.Socksaddr{Fqdn: "kaptain.example.com", Port: 443},
		}
		for _, a := range addrs {
			m.DestinationAddresses = append(m.DestinationAddresses, netip.MustParseAddr(a))
		}
		return m
	}
	rejects := func(m adapter.InboundContext) bool {
		reject, _ := tr.aclRejects(uuid, 42, "198.18.0.1", m, false)
		return reject
	}

	// Resolved inside the allowlist: the CIDR rule now governs a
	// domain-addressed connection.
	if rejects(meta("10.101.30.24")) {
		t.Error("resolved into 10.0.0.0/8: rejected, want allowed")
	}

	// Resolved outside it: still denied by the default.
	if !rejects(meta("203.0.113.9")) {
		t.Error("resolved outside 10.0.0.0/8: allowed, want rejected")
	}

	// Nothing resolved (no `resolve` rule configured): unchanged behaviour —
	// the name matches nothing, so the deny default applies.
	if !rejects(meta()) {
		t.Error("unresolved: allowed, want rejected")
	}
}

// The tracker half of per-address judging: a mixed answer is allowed and the
// allowed addresses go to the outbound in enforce mode; nothing in dry-run —
// dry-run must not change where traffic goes.
func TestACLPerAddressDialConstraint(t *testing.T) {
	const uuid = "28d860d7-ff89-4dc5-bb21-930627bcb0a7"
	cfg := func(mode string) *model.ACLConfig {
		return &model.ACLConfig{
			Mode:          mode,
			DefaultAction: "deny",
			Groups: []model.ACLGroup{{
				ID: "base",
				Rules: []model.ACLRule{
					{Action: "allow", Priority: 40, IPCIDRs: []string{"10.101.0.0/16"}, MatchResolved: true},
					{Action: "deny", Priority: 100, IPCIDRs: []string{"10.0.0.0/8"}, MatchResolved: true},
				},
			}},
		}
	}
	meta := adapter.InboundContext{
		Destination: singM.Socksaddr{Fqdn: "sso-gateway.qunhequnhe.com", Port: 443},
		DestinationAddresses: []netip.Addr{
			netip.MustParseAddr("10.101.30.4"), netip.MustParseAddr("183.129.228.249"),
		},
	}
	for _, tc := range []struct {
		mode string
		want []netip.Addr
	}{
		{"enforce", []netip.Addr{netip.MustParseAddr("10.101.30.4")}},
		{"dryrun", nil},
	} {
		store := acl.New()
		if err := store.Update(cfg(tc.mode), []model.UserSpec{{ID: 42, UUID: uuid, ACLGroups: []string{"base"}}}); err != nil {
			t.Fatalf("%s: acl update: %v", tc.mode, err)
		}
		tr := NewConnTracker(0)
		tr.SetACLFunc(store.Lookup)
		reject, dialOnly := tr.aclRejects(uuid, 42, "198.18.0.1", meta, false)
		if reject {
			t.Errorf("%s: rejected, want allowed", tc.mode)
		}
		if !slices.Equal(dialOnly, tc.want) {
			t.Errorf("%s: dialOnly = %v, want %v", tc.mode, dialOnly, tc.want)
		}
	}
}
