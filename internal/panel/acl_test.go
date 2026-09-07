package panel

import (
	"encoding/json"
	"testing"
)

// decodeConfig mirrors what GetConfig does with a panel response body.
func decodeConfig(t *testing.T, body string) *NodeConfig {
	t.Helper()
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var cfg NodeConfig
	if err := decodeWeakRaw(raw, &cfg); err != nil {
		t.Fatalf("decodeWeakRaw: %v", err)
	}
	return &cfg
}

// The compatibility contract: a panel that says nothing about ACL leaves the
// field nil, which the node reads as "no enforcement at all".
func TestConfigWithoutACLLeavesFieldNil(t *testing.T) {
	cfg := decodeConfig(t, `{"protocol":"vless","server_port":443}`)
	if cfg.ACL != nil {
		t.Errorf("ACL = %+v, want nil", cfg.ACL)
	}
}

func TestConfigACLDecodes(t *testing.T) {
	cfg := decodeConfig(t, `{
		"protocol": "vless",
		"server_port": 443,
		"acl": {
			"mode": "enforce",
			"default_action": "deny",
			"implicit_dns_allow": false,
			"groups": [{
				"id": "vip",
				"priority": 10,
				"rules": [{
					"action": "allow",
					"priority": 5,
					"ip_cidrs": ["10.1.0.0/16"],
					"domain_suffixes": ["corp.example.com"],
					"ports": ["443", "8000-9000"],
					"protocols": ["tcp"],
					"match_resolved": true
				}]
			}]
		}
	}`)

	if cfg.ACL == nil {
		t.Fatal("ACL not decoded")
	}
	if cfg.ACL.Mode != "enforce" || cfg.ACL.DefaultAction != "deny" {
		t.Errorf("mode/default = %q/%q", cfg.ACL.Mode, cfg.ACL.DefaultAction)
	}
	if cfg.ACL.ImplicitDNSAllow == nil || *cfg.ACL.ImplicitDNSAllow {
		t.Error("implicit_dns_allow=false must decode to a non-nil false")
	}
	if len(cfg.ACL.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(cfg.ACL.Groups))
	}
	g := cfg.ACL.Groups[0]
	if g.ID != "vip" || g.Priority != 10 || len(g.Rules) != 1 {
		t.Fatalf("group = %+v", g)
	}
	r := g.Rules[0]
	if r.Action != "allow" || r.Priority != 5 {
		t.Errorf("rule action/priority = %q/%d", r.Action, r.Priority)
	}
	if len(r.IPCIDRs) != 1 || r.IPCIDRs[0] != "10.1.0.0/16" {
		t.Errorf("ip_cidrs = %v", r.IPCIDRs)
	}
	if len(r.DomainSuffixes) != 1 || r.DomainSuffixes[0] != "corp.example.com" {
		t.Errorf("domain_suffixes = %v", r.DomainSuffixes)
	}
	if !r.MatchResolved {
		t.Error("match_resolved must decode")
	}
	if len(r.Ports) != 2 || r.Ports[1] != "8000-9000" {
		t.Errorf("ports = %v", r.Ports)
	}
	if len(r.Protocols) != 1 || r.Protocols[0] != "tcp" {
		t.Errorf("protocols = %v", r.Protocols)
	}
}

// Omitting implicit_dns_allow must leave it nil so DNSAllowed() can default
// it to true — decoding it as false would strand users without resolution.
func TestConfigACLOmittedDNSFlagStaysNil(t *testing.T) {
	cfg := decodeConfig(t, `{"protocol":"vless","acl":{"mode":"enforce","default_action":"deny"}}`)
	if cfg.ACL == nil {
		t.Fatal("ACL not decoded")
	}
	if cfg.ACL.ImplicitDNSAllow != nil {
		t.Errorf("ImplicitDNSAllow = %v, want nil", *cfg.ACL.ImplicitDNSAllow)
	}
}

// The config endpoint decodes weakly, so a panel sending numbers as strings
// still works. This is the forgiving path.
func TestConfigACLWeakTypes(t *testing.T) {
	cfg := decodeConfig(t, `{
		"protocol": "vless",
		"acl": {"mode":"enforce","default_action":"deny","implicit_dns_allow":"true",
		        "groups":[{"id":"g","priority":"20","rules":[{"action":"deny","ports":[443]}]}]}
	}`)
	if cfg.ACL == nil || len(cfg.ACL.Groups) != 1 {
		t.Fatal("ACL not decoded")
	}
	if cfg.ACL.Groups[0].Priority != 20 {
		t.Errorf("priority = %d, want 20", cfg.ACL.Groups[0].Priority)
	}
	if cfg.ACL.ImplicitDNSAllow == nil || !*cfg.ACL.ImplicitDNSAllow {
		t.Error(`"true" should weak-decode to true`)
	}
	if got := cfg.ACL.Groups[0].Rules[0].Ports; len(got) != 1 || got[0] != "443" {
		t.Errorf("ports = %v, want [443]", got)
	}
}

// ─── user endpoint ──────────────────────────────────────────────────────

// The user endpoint uses strict encoding/json, not the weak decoder. A user
// list without acl_groups must still parse — that is the old-panel path.
func TestUsersWithoutACLGroupsParse(t *testing.T) {
	var resp UsersResponse
	body := `{"users":[{"id":1,"uuid":"u-1","speed_limit":0,"device_limit":3}]}`
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Users) != 1 {
		t.Fatalf("users = %d", len(resp.Users))
	}
	if resp.Users[0].ACLGroups != nil {
		t.Errorf("ACLGroups = %v, want nil", resp.Users[0].ACLGroups)
	}
}

func TestUsersWithACLGroupsParse(t *testing.T) {
	var resp UsersResponse
	body := `{"users":[
		{"id":1,"uuid":"u-1","acl_groups":["vip","corp"]},
		{"id":2,"uuid":"u-2","acl_groups":[]}
	]}`
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := resp.Users[0].ACLGroups; len(got) != 2 || got[0] != "vip" || got[1] != "corp" {
		t.Errorf("ACLGroups = %v", got)
	}
	if got := resp.Users[1].ACLGroups; len(got) != 0 {
		t.Errorf("empty array should decode to an empty slice, got %v", got)
	}
}

// A panel that serialises acl_groups as a JSON *string* instead of an array
// fails the whole user list, taking every user down with it — the one panel
// mistake in this feature that causes a hard node outage rather than a
// silently ineffective rule. Pinned here so the failure mode stays known
// (docs-user-acl.md §10).
func TestUsersWithStringifiedACLGroupsFailLoudly(t *testing.T) {
	var resp UsersResponse
	body := `{"users":[{"id":1,"uuid":"u-1","acl_groups":"[\"vip\"]"}]}`
	if err := json.Unmarshal([]byte(body), &resp); err == nil {
		t.Fatal("a stringified acl_groups must fail to decode, not be silently ignored")
	}
}
