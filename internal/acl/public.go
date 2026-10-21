package acl

import (
	"net/netip"
	"sort"

	"go4.org/netipx"
)

// nonPublic lists every range that is not reachable on the public internet:
// RFC 1918, CGNAT, loopback, link-local, benchmarking, documentation,
// multicast, reserved, and their IPv6 counterparts.
//
// It decides dial order, not the verdict: among the addresses the ACL allowed
// for a name, internal ones are tried first (preferInternal). A name like
// sso-gateway that resolves to both its internal and its public address is
// then reached the way an office machine reaches it, instead of hairpinning
// out through the node's own egress to the company's public IP.
var nonPublic = mustIPSet(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"64:ff9b::/96", // NAT64: the embedded IPv4 may be anything
	"100::/64",
	"2001:db8::/32",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
)

func mustIPSet(prefixes ...string) *netipx.IPSet {
	var b netipx.IPSetBuilder
	for _, p := range prefixes {
		b.AddPrefix(netip.MustParsePrefix(p))
	}
	set, err := b.IPSet()
	if err != nil {
		panic(err)
	}
	return set
}

// IsPublic reports whether addr is reachable on the public internet.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && !nonPublic.Contains(addr)
}

// internalFirst reports whether no public address precedes an internal one.
func internalFirst(ips []netip.Addr) bool {
	seenPublic := false
	for _, ip := range ips {
		if IsPublic(ip) {
			seenPublic = true
		} else if seenPublic {
			return false
		}
	}
	return true
}

// preferInternal moves internal addresses ahead of public ones, keeping the
// relative order inside each class so the resolver's family preference holds.
func preferInternal(ips []netip.Addr) {
	sort.SliceStable(ips, func(i, j int) bool {
		return !IsPublic(ips[i]) && IsPublic(ips[j])
	})
}
