package singbox

import (
	"net/netip"
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

	// Resolved inside the allowlist: the CIDR rule now governs a
	// domain-addressed connection.
	if tr.aclRejects(uuid, 42, "198.18.0.1", meta("10.101.30.24"), false) {
		t.Error("resolved into 10.0.0.0/8: rejected, want allowed")
	}

	// Resolved outside it: still denied by the default.
	if !tr.aclRejects(uuid, 42, "198.18.0.1", meta("203.0.113.9"), false) {
		t.Error("resolved outside 10.0.0.0/8: allowed, want rejected")
	}

	// Nothing resolved (no `resolve` rule configured): unchanged behaviour —
	// the name matches nothing, so the deny default applies.
	if !tr.aclRejects(uuid, 42, "198.18.0.1", meta(), false) {
		t.Error("unresolved: allowed, want rejected")
	}
}
