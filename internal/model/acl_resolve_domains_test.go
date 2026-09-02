package model

import (
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestNormalizeResolveDomains(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil stays nil", nil, nil},
		{"plain", []string{"example.com"}, []string{"example.com"}},
		{
			// Operators copy these lists out of client configs, where the
			// wildcard markers are part of the syntax.
			"clash wildcards stripped",
			[]string{"+.example.com", "*.other.com", ".third.com"},
			[]string{"example.com", "other.com", "third.com"},
		},
		{"lowercased", []string{"Example.COM"}, []string{"example.com"}},
		{"trimmed", []string{"  example.com  "}, []string{"example.com"}},
		{
			"deduplicated across forms",
			[]string{"example.com", "+.example.com", "EXAMPLE.com"},
			[]string{"example.com"},
		},
		{
			// Sorting keeps the kernel hash stable when a panel returns the
			// same set in a different order.
			"sorted",
			[]string{"z.com", "a.com", "m.com"},
			[]string{"a.com", "m.com", "z.com"},
		},
		{
			// Junk widens nothing, so dropping it beats failing the push.
			"unusable entries dropped",
			[]string{"", "   ", "localhost", "http://x.com", "a b.com", "ok.com"},
			[]string{"ok.com"},
		},
		{"all junk becomes nil", []string{"", "localhost"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeResolveDomains(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("normalizeResolveDomains(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A panel returning the same domains in a different order must not look like a
// change: this field is in the kernel hash, so a spurious diff would rebuild
// the kernel and drop every connection on the node.
func TestResolveDomainOrderDoesNotChangeSpec(t *testing.T) {
	a := NodeSpecFromPanel(&panel.NodeConfig{
		Protocol:          "vless",
		ACLResolveDomains: []string{"b.example.com", "a.example.com"},
	})
	b := NodeSpecFromPanel(&panel.NodeConfig{
		Protocol:          "vless",
		ACLResolveDomains: []string{"a.example.com", "b.example.com"},
	})
	if !reflect.DeepEqual(a.ACLResolveDomains, b.ACLResolveDomains) {
		t.Errorf("order changed the spec: %q vs %q", a.ACLResolveDomains, b.ACLResolveDomains)
	}
}
