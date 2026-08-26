// Package acl implements per-user destination access control.
//
// Enforcement happens in-process, on the per-connection hooks the kernels
// already run for device limits (xray's LimitDispatcher, sing-box's
// ConnTracker) — never through kernel routing rules. That choice is what
// makes policy changes a memory swap instead of a kernel reload: xray's
// Reload is a full restart whenever the config hash moves, which would drop
// every connection on the node each time an operator edited a group.
//
// Cost model: a check is one map lookup plus a binary search over sorted IP
// ranges, so it scales with the number of CIDRs per group, not with the
// number of users. Policies are interned per group-combination, so N users
// sharing a group share one *Policy.
package acl

import (
	"net/netip"
	"sort"
	"sync/atomic"

	"go4.org/netipx"
)

// Action is the outcome of an ACL evaluation.
type Action uint8

const (
	// ActionAllow permits the connection.
	ActionAllow Action = iota
	// ActionDeny rejects it.
	ActionDeny
)

func (a Action) String() string {
	if a == ActionDeny {
		return "deny"
	}
	return "allow"
}

// Mode is the node-wide enforcement mode pushed by the panel.
type Mode uint8

const (
	// ModeOff disables ACL entirely — Lookup returns nil for every user.
	ModeOff Mode = iota
	// ModeDryRun evaluates and reports but never blocks.
	ModeDryRun
	// ModeEnforce evaluates and blocks.
	ModeEnforce
)

func (m Mode) String() string {
	switch m {
	case ModeDryRun:
		return "dryrun"
	case ModeEnforce:
		return "enforce"
	default:
		return "off"
	}
}

// Dest is a connection target as seen at the kernel hook.
//
// Exactly one of IP / Domain is meaningful: proxy protocols carry either a
// resolved address or the hostname the client asked for. The ACL never
// resolves a domain to match an IP rule — a DNS round trip per connection
// would cost five orders of magnitude more than the match itself.
type Dest struct {
	IP     netip.Addr // invalid when the client addressed a domain
	Domain string     // empty when the client addressed an IP
	Port   uint16
	UDP    bool
}

// Policy is a compiled, immutable rule list for one group-combination.
// The zero value is not useful; obtain one from a Store.
type Policy struct {
	rules  []rule
	def    Action
	dryRun bool
}

// allowAll is the shared policy for users with no restrictions. Interning it
// keeps unrestricted users at one pointer each instead of one object each.
var allowAll = &Policy{def: ActionAllow}

// OriginDefault is the rule origin reported when no rule matched and the
// policy default decided the outcome.
const OriginDefault = "default"

// Check evaluates dest against the policy and returns the first matching
// rule's action, or the policy default when nothing matches.
//
// A nil Policy allows everything, so callers can skip a branch on the hot
// path: acl.Lookup(id).Check(dest) is safe when the user is unrestricted.
func (p *Policy) Check(dest Dest) Action {
	action, _ := p.Evaluate(dest)
	return action
}

// Evaluate is Check plus the identity of the rule that decided the outcome,
// for reporting which rule blocked (or would block) a connection.
func (p *Policy) Evaluate(dest Dest) (Action, string) {
	if p == nil {
		return ActionAllow, OriginDefault
	}
	for i := range p.rules {
		if p.rules[i].matches(dest) {
			return p.rules[i].action, p.rules[i].origin
		}
	}
	return p.def, OriginDefault
}

// DryRun reports whether a denial should be logged rather than enforced.
func (p *Policy) DryRun() bool {
	return p != nil && p.dryRun
}

// ModeLabel names the enforcement mode this policy was compiled for, for use
// in reported records.
func (p *Policy) ModeLabel() string {
	if p.DryRun() {
		return ModeDryRun.String()
	}
	return ModeEnforce.String()
}

// Restricted reports whether the policy can ever deny anything. Callers use
// it to skip work for allow-all users.
func (p *Policy) Restricted() bool {
	if p == nil {
		return false
	}
	return p.def == ActionDeny || len(p.rules) > 0
}

// rule is one compiled ACL rule.
//
// Matching semantics — the three groups are ANDed, values inside each group
// are ORed:
//
//	destination (ip_cidrs | domains | domain_suffixes)  AND  ports  AND  protocols
//
// The destination matchers are one OR-group rather than three independent
// AND terms on purpose: a target is either an address or a hostname, never
// both, so ANDing them across kinds would make any rule that lists a CIDR
// *and* a suffix unmatchable.
type rule struct {
	action Action

	// destination group
	ips      *netipx.IPSet
	domains  map[string]struct{}
	suffixes map[string]struct{}
	hasDest  bool

	// port group; sorted by lo, searched by binary search
	ports []portRange

	// protocol group
	tcp, udp bool
	hasProto bool

	// origin identifies the rule in dry-run logs, e.g. "vip#2".
	origin string
}

type portRange struct{ lo, hi uint16 }

func (r *rule) matches(d Dest) bool {
	if r.hasProto {
		if d.UDP && !r.udp {
			return false
		}
		if !d.UDP && !r.tcp {
			return false
		}
	}
	if len(r.ports) > 0 && !matchPort(r.ports, d.Port) {
		return false
	}
	if r.hasDest && !r.matchDest(d) {
		return false
	}
	return true
}

func (r *rule) matchDest(d Dest) bool {
	if d.Domain != "" {
		if len(r.domains) > 0 {
			if _, ok := r.domains[d.Domain]; ok {
				return true
			}
		}
		return matchSuffix(r.suffixes, d.Domain)
	}
	if r.ips != nil && d.IP.IsValid() {
		return r.ips.Contains(d.IP)
	}
	return false
}

// matchSuffix reports whether host equals or is a subdomain of any entry.
// It walks label boundaries so "corp.example.com" matches
// "a.corp.example.com" but not "notcorp.example.com".
func matchSuffix(set map[string]struct{}, host string) bool {
	if len(set) == 0 {
		return false
	}
	if _, ok := set[host]; ok {
		return true
	}
	for i := 0; i < len(host)-1; i++ {
		if host[i] == '.' {
			if _, ok := set[host[i+1:]]; ok {
				return true
			}
		}
	}
	return false
}

func matchPort(ranges []portRange, port uint16) bool {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].hi >= port })
	return i < len(ranges) && ranges[i].lo <= port
}

// ─── Store ──────────────────────────────────────────────────────────────

// Store holds the live policy set. Reads are lock-free (one atomic load plus
// a map lookup); writes swap a freshly built snapshot in whole, so a panel
// push never blocks a connection.
type Store struct {
	snap atomic.Pointer[snapshot]
}

type snapshot struct {
	mode Mode
	// byIdentity is keyed by BOTH forms of user identity the kernels carry:
	// the UUID (sing-box inbound user name) and "user@<id>" (xray stats
	// email). The two key spaces cannot collide, so one map serves both
	// kernels with no per-kernel branching on the hot path.
	byIdentity map[string]*Policy
	// fallback applies to an identity that is not in the map. It is nil
	// unless the node default is deny, so an unknown user cannot slip past
	// a default-deny node.
	fallback *Policy
}

// New returns an empty Store that permits everything until Update is called.
func New() *Store { return &Store{} }

// Lookup resolves a kernel-native user identity to its policy. It returns nil
// when ACL is off or the user is unrestricted — callers may pass the nil
// straight to Check.
func (s *Store) Lookup(identity string) *Policy {
	snap := s.snap.Load()
	if snap == nil || snap.mode == ModeOff {
		return nil
	}
	if p, ok := snap.byIdentity[identity]; ok {
		return p
	}
	return snap.fallback
}

// Mode returns the current enforcement mode.
func (s *Store) Mode() Mode {
	snap := s.snap.Load()
	if snap == nil {
		return ModeOff
	}
	return snap.mode
}

// Enabled reports whether any enforcement or reporting is active.
func (s *Store) Enabled() bool { return s.Mode() != ModeOff }
