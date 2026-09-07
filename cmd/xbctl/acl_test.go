package main

import (
	"net/netip"
	"testing"
)

// The port/address grammar is the one part of `acl eval` that can silently
// mis-parse rather than fail: eating an IPv6 address's last label as a port
// would evaluate a different destination than the operator typed and report a
// confident, wrong verdict.
func TestParseACLTarget(t *testing.T) {
	cases := []struct {
		in       string
		domain   string
		ip       string
		resolved []string
		port     uint16
		udp      bool
	}{
		{in: "corp.example.com", domain: "corp.example.com", port: 443},
		{in: "corp.example.com:8080", domain: "corp.example.com", port: 8080},
		{in: "CORP.Example.COM", domain: "corp.example.com", port: 443},
		{in: "10.0.0.1", ip: "10.0.0.1", port: 443},
		{in: "10.0.0.1:7680", ip: "10.0.0.1", port: 7680},
		{in: "2001:db8::1", ip: "2001:db8::1", port: 443},
		{in: "[2001:db8::1]:8443", ip: "2001:db8::1", port: 8443},
		{in: "dns.corp:53/udp", domain: "dns.corp", port: 53, udp: true},
		{
			in: "a.corp.example.com@10.0.0.1", domain: "a.corp.example.com",
			resolved: []string{"10.0.0.1"}, port: 443,
		},
		{
			in: "a.corp.example.com@10.0.0.1:8080", domain: "a.corp.example.com",
			resolved: []string{"10.0.0.1"}, port: 8080,
		},
		{
			in: "a.corp.example.com:8080@10.0.0.1", domain: "a.corp.example.com",
			resolved: []string{"10.0.0.1"}, port: 8080,
		},
		{
			in: "a.corp.example.com@10.0.0.1,10.0.0.50", domain: "a.corp.example.com",
			resolved: []string{"10.0.0.1", "10.0.0.50"}, port: 443,
		},
		{
			in: "a.corp.example.com@2001:db8::1", domain: "a.corp.example.com",
			resolved: []string{"2001:db8::1"}, port: 443,
		},
		{
			in: "a.corp.example.com@10.0.0.1/udp", domain: "a.corp.example.com",
			resolved: []string{"10.0.0.1"}, port: 443, udp: true,
		},
	}

	for _, c := range cases {
		dest, _, err := parseACLTarget(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if dest.Domain != c.domain {
			t.Errorf("%s: domain = %q, want %q", c.in, dest.Domain, c.domain)
		}
		gotIP := ""
		if dest.IP.IsValid() {
			gotIP = dest.IP.String()
		}
		if gotIP != c.ip {
			t.Errorf("%s: ip = %q, want %q", c.in, gotIP, c.ip)
		}
		if len(dest.ResolvedIPs) != len(c.resolved) {
			t.Errorf("%s: resolved = %v, want %v", c.in, dest.ResolvedIPs, c.resolved)
			continue
		}
		for i, want := range c.resolved {
			if dest.ResolvedIPs[i] != netip.MustParseAddr(want) {
				t.Errorf("%s: resolved[%d] = %v, want %v", c.in, i, dest.ResolvedIPs[i], want)
			}
		}
		if dest.Port != c.port {
			t.Errorf("%s: port = %d, want %d", c.in, dest.Port, c.port)
		}
		if dest.UDP != c.udp {
			t.Errorf("%s: udp = %v, want %v", c.in, dest.UDP, c.udp)
		}
	}
}

func TestParseACLTargetRejects(t *testing.T) {
	for _, in := range []string{"", "@10.0.0.1", "corp.example.com@", "corp.example.com@nope"} {
		if _, _, err := parseACLTarget(in); err == nil {
			t.Errorf("%q: expected an error", in)
		}
	}
}

// Unbracketed means "this is an address": 2001:db8::1:443 is a valid IPv6
// literal, not host 2001:db8::1 on port 443. Pinned so the bracket rule stays
// the only way to express a v6 address with a port.
func TestParseACLTargetUnbracketedV6IsAnAddress(t *testing.T) {
	dest, _, err := parseACLTarget("2001:db8::1:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest.IP != netip.MustParseAddr("2001:db8::1:443") || dest.Port != 443 {
		t.Errorf("got ip=%v port=%d, want 2001:db8::1:443 / 443(default)", dest.IP, dest.Port)
	}
}

func TestACLSuffixCoversLabelBoundary(t *testing.T) {
	suffixes := []string{"corp.example.com"}
	for _, host := range []string{"corp.example.com", "a.corp.example.com", "a.b.corp.example.com"} {
		if !aclSuffixCovers(suffixes, host) {
			t.Errorf("%s must be covered", host)
		}
	}
	for _, host := range []string{"notcorp.example.com", "example.com", "corp.example.com.evil.test"} {
		if aclSuffixCovers(suffixes, host) {
			t.Errorf("%s must not be covered", host)
		}
	}
}
