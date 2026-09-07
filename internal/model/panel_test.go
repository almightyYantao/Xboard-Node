package model

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestNodeSpecFromPanelValidated(t *testing.T) {
	t.Run("valid custom outbounds and route targets", func(t *testing.T) {
		node, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{
				{Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"}},
				{Tag: "proxy", Protocol: "socks", ProxyTag: "warp", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}},
			},
			CustomRouteRules: []panel.CustomRouteRule{{
				Action: panel.RouteAction{Type: "route", Target: "proxy"},
				Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err != nil {
			t.Fatalf("NodeSpecFromPanelValidated: %v", err)
		}
		if node == nil || len(node.CustomOutbounds) != 2 {
			t.Fatalf("unexpected node spec: %#v", node)
		}
	})

	t.Run("invalid custom outbounds", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "proxy", Protocol: "socks", ProxyTag: "missing", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `custom_outbounds[0].proxy_tag references unknown outbound "missing"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reject unsupported protocol for kernel", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "hy2", Protocol: "hysteria2", Settings: map[string]any{"server": "2.2.2.2", "server_port": 8443},
			}},
		}, config.KernelConfig{Type: "xray"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `protocol "hysteria2" is not supported by kernel "xray"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reject unknown route target", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"},
			}},
			CustomRouteRules: []panel.CustomRouteRule{{
				Action: panel.RouteAction{Type: "route", Target: "missing"},
				Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `custom_route_rules[0].action.target references unknown outbound "missing"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// The ACL rule struct is mirrored in three places (panel wire, model, and the
// compiler). A field added to one and forgotten in a conversion is invisible:
// the config validates, the node runs, and the rule quietly loses the part the
// operator was relying on. Round-trip every matcher so the omission fails here.
func TestACLRuleSurvivesPanelRoundTrip(t *testing.T) {
	want := panel.ACLRule{
		Action:         "allow",
		Priority:       7,
		IPCIDRs:        []string{"10.0.0.1/32"},
		Domains:        []string{"a.corp.example.com"},
		DomainSuffixes: []string{"corp.example.com"},
		Ports:          []string{"443"},
		Protocols:      []string{"tcp"},
		MatchResolved:  true,
	}
	spec := NodeSpecFromPanel(&panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		ACL: &panel.ACLConfig{
			Mode:          "enforce",
			DefaultAction: "deny",
			Groups:        []panel.ACLGroup{{ID: "corp", Priority: 10, Rules: []panel.ACLRule{want}}},
		},
	})
	if spec.ACL == nil || len(spec.ACL.Groups) != 1 || len(spec.ACL.Groups[0].Rules) != 1 {
		t.Fatalf("acl lost in FromPanel: %+v", spec.ACL)
	}
	if !spec.ACL.Groups[0].Rules[0].MatchResolved {
		t.Error("match_resolved lost in aclFromPanel")
	}

	got := spec.ToPanel().ACL
	if got == nil || len(got.Groups) != 1 || len(got.Groups[0].Rules) != 1 {
		t.Fatalf("acl lost in ToPanel: %+v", got)
	}
	if diff := got.Groups[0].Rules[0]; !reflect.DeepEqual(diff, want) {
		t.Errorf("rule round-trip:\n got %+v\nwant %+v", diff, want)
	}
}
