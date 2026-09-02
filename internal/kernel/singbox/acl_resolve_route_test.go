package singbox

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// The panel-pushed acl_resolve_domains list becomes a kernel-native `resolve`
// route rule, so a sing-box upgrade that changed the rule schema would silently
// stop the ACL's resolution fallback and the only symptom would be domain
// traffic being denied again. Parse the generated route with sing-box's own
// option types to pin it.
func TestACLResolveDomainsBecomeRouteRule(t *testing.T) {
	route := buildRoutes(nil, nil, nil, []string{"10.0.0.0/8"},
		[]string{"example.com", "internal.test"})

	data, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("marshal generated route: %v", err)
	}

	var opts option.RouteOptions
	if err := json.Unmarshal(data, &opts); err != nil {
		t.Fatalf("sing-box rejected the generated route: %v\n%s", err, data)
	}
	if len(opts.Rules) == 0 {
		t.Fatal("no rules parsed")
	}

	// It must come first: resolve is non-terminal, so the private_allow entry
	// and the SSRF blocklist after it then match on the resolved addresses
	// instead of missing on the FQDN.
	first := opts.Rules[0]
	if got := first.DefaultOptions.RuleAction.Action; got != "resolve" {
		t.Fatalf("first rule action = %q, want resolve", got)
	}
	if first.DefaultOptions.RuleAction.ResolveOptions.Strategy == 0 {
		t.Error("resolve strategy parsed as zero; check the option field name")
	}
	if got := []string(first.DefaultOptions.DomainSuffix); len(got) != 2 {
		t.Errorf("domain_suffix = %v, want both domains", got)
	}
}

// No list, no rule: a node whose panel says nothing about resolution must
// generate exactly the config it generated before this feature existed.
func TestNoACLResolveDomainsEmitsNoRule(t *testing.T) {
	route := buildRoutes(nil, nil, nil, nil, nil)
	data, _ := json.Marshal(route)

	var opts option.RouteOptions
	if err := json.Unmarshal(data, &opts); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i, r := range opts.Rules {
		if r.DefaultOptions.RuleAction.Action == "resolve" {
			t.Fatalf("rule[%d] is a resolve rule, want none", i)
		}
	}
}
