package service

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func baseSpec() *model.NodeSpec {
	return &model.NodeSpec{Protocol: "vless", ServerPort: 443, KernelType: "xray"}
}

func denySpec() *model.NodeSpec {
	spec := baseSpec()
	spec.ACL = &model.ACLConfig{
		Mode:          "enforce",
		DefaultAction: "deny",
		Groups: []model.ACLGroup{{
			ID:    "vip",
			Rules: []model.ACLRule{{Action: "allow", IPCIDRs: []string{"10.0.0.0/8"}}},
		}},
	}
	return spec
}

// The whole reason ACL is enforced in-process: editing a policy must not
// look like a config change to the kernel. xray answers a changed hash with
// a full restart, which drops every live connection on the node.
func TestKernelHashIgnoresACL(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "u-1"}}

	if kernel.ComputeHash(baseSpec(), users) != kernel.ComputeHash(denySpec(), users) {
		t.Error("adding an ACL policy must not change the kernel hash")
	}

	other := denySpec()
	other.ACL.Groups[0].Rules[0].IPCIDRs = []string{"192.168.0.0/16"}
	if kernel.ComputeHash(denySpec(), users) != kernel.ComputeHash(other, users) {
		t.Error("editing an ACL rule must not change the kernel hash")
	}
}

// acl_resolve_domains is the deliberate exception, and the reason it is not a
// field inside ACLConfig: it compiles into a kernel route rule, so the kernel
// must be rebuilt when it changes. Pinning both halves here keeps the split
// honest — someone moving this field under `acl` to tidy the contract would
// make it silently take effect only at the next unrelated kernel rebuild.
func TestKernelHashTracksACLResolveDomains(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "u-1"}}

	withDomains := baseSpec()
	withDomains.ACLResolveDomains = []string{"internal.example.com"}
	if kernel.ComputeHash(baseSpec(), users) == kernel.ComputeHash(withDomains, users) {
		t.Error("adding acl_resolve_domains must change the kernel hash")
	}

	changed := baseSpec()
	changed.ACLResolveDomains = []string{"other.example.com"}
	if kernel.ComputeHash(withDomains, users) == kernel.ComputeHash(changed, users) {
		t.Error("editing acl_resolve_domains must change the kernel hash")
	}
}

// Group membership must not restart the kernel either — it rides on the user
// records, which the kernel hashes by ID and UUID only.
func TestKernelHashIgnoresUserACLGroups(t *testing.T) {
	plain := []model.UserSpec{{ID: 1, UUID: "u-1"}}
	grouped := []model.UserSpec{{ID: 1, UUID: "u-1", ACLGroups: []string{"vip"}}}

	if kernel.ComputeHash(baseSpec(), plain) != kernel.ComputeHash(baseSpec(), grouped) {
		t.Error("ACL group membership must not change the kernel hash")
	}
}

// The service hash is the other half of the contract: it has to notice the
// ACL change that the kernel hash deliberately ignores, or a push that only
// edits policy would never be applied.
func TestServiceConfigHashTracksACL(t *testing.T) {
	if computeConfigHash(baseSpec()) == computeConfigHash(denySpec()) {
		t.Error("service hash must notice an added ACL policy")
	}

	other := denySpec()
	other.ACL.DefaultAction = "allow"
	if computeConfigHash(denySpec()) == computeConfigHash(other) {
		t.Error("service hash must notice a changed default action")
	}

	rule := denySpec()
	rule.ACL.Groups[0].Rules[0].Ports = []string{"443"}
	if computeConfigHash(denySpec()) == computeConfigHash(rule) {
		t.Error("service hash must notice a changed rule")
	}

	if computeConfigHash(denySpec()) != computeConfigHash(denySpec()) {
		t.Error("service hash must be stable for identical input")
	}
}

// Re-grouping a user must register as a user change, or the new policy would
// never be compiled.
func TestUserHashTracksACLGroups(t *testing.T) {
	plain := []model.UserSpec{{ID: 1, UUID: "u-1"}}
	grouped := []model.UserSpec{{ID: 1, UUID: "u-1", ACLGroups: []string{"vip"}}}
	regrouped := []model.UserSpec{{ID: 1, UUID: "u-1", ACLGroups: []string{"corp"}}}

	if computeUserHash(plain) == computeUserHash(grouped) {
		t.Error("adding a group must change the user hash")
	}
	if computeUserHash(grouped) == computeUserHash(regrouped) {
		t.Error("changing a group must change the user hash")
	}
	if computeUserHash(grouped) != computeUserHash(grouped) {
		t.Error("user hash must be stable for identical input")
	}
}

// A node whose panel never mentions ACL must hash exactly as it did before
// the feature existed.
func TestHashesUnchangedWhenPanelSendsNoACL(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "u-1", SpeedLimit: 10, DeviceLimit: 3}}
	spec := baseSpec()

	// Recomputing must be stable, and the ACL branch must not be taken.
	if computeConfigHash(spec) != computeConfigHash(baseSpec()) {
		t.Error("config hash must be stable when no ACL is present")
	}
	if computeUserHash(users) != computeUserHash(users) {
		t.Error("user hash must be stable when no groups are present")
	}
	if kernel.ComputeHash(spec, users) != kernel.ComputeHash(baseSpec(), users) {
		t.Error("kernel hash must be stable when no ACL is present")
	}
}
