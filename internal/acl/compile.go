package acl

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"go4.org/netipx"
)

// xrayEmail mirrors the stats email xray assigns to each inbound client
// (see internal/kernel/xray/config.go userEmail). Indexing policies under
// both this and the UUID lets one map serve both kernels.
func xrayEmail(userID int) string { return "user@" + strconv.Itoa(userID) }

// Update recompiles the policy set and swaps it in atomically.
//
// It never returns a partially applied state: on error the previous snapshot
// stays live, which matters because the alternative — falling back to "no
// policy" — would silently open a node the operator believes is locked down.
func (s *Store) Update(cfg *model.ACLConfig, users []model.UserSpec) error {
	mode := parseMode(cfg)
	if mode == ModeOff {
		s.snap.Store(&snapshot{mode: ModeOff})
		return nil
	}

	if err := model.ValidateACLConfig(cfg); err != nil {
		return fmt.Errorf("acl: %w", err)
	}

	dryRun := mode == ModeDryRun
	nodeDefault := parseAction(cfg.DefaultAction)

	groups := make(map[string]*compiledGroup, len(cfg.Groups))
	for _, g := range cfg.Groups {
		cg, err := compileGroup(g)
		if err != nil {
			return fmt.Errorf("acl: %w", err)
		}
		groups[cg.id] = cg
	}

	// One policy per distinct group-combination, shared by every user in it.
	// This is what keeps a 5000-user node at a few MB instead of ~120 MB.
	cache := make(map[string]*Policy)
	byIdentity := make(map[string]*Policy, len(users)*2)

	for _, u := range users {
		ids := normalizeGroupIDs(u.ACLGroups, groups)
		key := strings.Join(ids, "\x00")
		policy, ok := cache[key]
		if !ok {
			policy = buildPolicy(ids, groups, nodeDefault, cfg.DNSAllowed(), dryRun)
			cache[key] = policy
		}
		if u.UUID != "" {
			byIdentity[u.UUID] = policy
		}
		byIdentity[xrayEmail(u.ID)] = policy
	}

	next := &snapshot{mode: mode, byIdentity: byIdentity}
	// An identity we have no record of must not be more privileged than a
	// known one. Under a deny default it inherits the same group-less policy
	// every other unaffiliated user gets.
	if nodeDefault == ActionDeny {
		next.fallback = buildPolicy(nil, groups, nodeDefault, cfg.DNSAllowed(), dryRun)
	}
	s.snap.Store(next)

	nlog.Core().Info("acl policy updated",
		"mode", mode.String(),
		"default", nodeDefault.String(),
		"groups", len(groups),
		"users", len(users),
		"distinct_policies", len(cache))
	return nil
}

type compiledGroup struct {
	id       string
	priority int
	def      Action
	hasDef   bool
	rules    []rule
}

func compileGroup(g model.ACLGroup) (*compiledGroup, error) {
	cg := &compiledGroup{
		id:       strings.TrimSpace(g.ID),
		priority: g.Priority,
	}
	if def := strings.TrimSpace(g.DefaultAction); def != "" {
		cg.def = parseAction(def)
		cg.hasDef = true
	}

	// Stable sort keeps declaration order as the tiebreaker for equal
	// priorities, so a panel that omits priority still gets array order.
	ordered := make([]indexedRule, len(g.Rules))
	for i, r := range g.Rules {
		ordered[i] = indexedRule{idx: i, rule: r}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].rule.Priority < ordered[j].rule.Priority
	})

	cg.rules = make([]rule, 0, len(ordered))
	for _, item := range ordered {
		compiled, err := compileRule(item.rule, fmt.Sprintf("%s#%d", cg.id, item.idx))
		if err != nil {
			return nil, err
		}
		cg.rules = append(cg.rules, compiled)
	}
	return cg, nil
}

type indexedRule struct {
	idx  int
	rule model.ACLRule
}

func compileRule(r model.ACLRule, origin string) (rule, error) {
	out := rule{action: parseAction(r.Action), origin: origin}

	if len(r.IPCIDRs) > 0 {
		var b netipx.IPSetBuilder
		for _, entry := range r.IPCIDRs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(entry))
			if err != nil {
				return rule{}, fmt.Errorf("rule %s: invalid CIDR %q", origin, entry)
			}
			b.AddPrefix(prefix.Masked())
		}
		set, err := b.IPSet()
		if err != nil {
			return rule{}, fmt.Errorf("rule %s: %w", origin, err)
		}
		out.ips = set
		out.hasDest = true
	}

	if len(r.Domains) > 0 {
		out.domains = make(map[string]struct{}, len(r.Domains))
		for _, d := range r.Domains {
			if name := normalizeHost(d); name != "" {
				out.domains[name] = struct{}{}
				out.hasDest = true
			}
		}
	}
	if len(r.DomainSuffixes) > 0 {
		out.suffixes = make(map[string]struct{}, len(r.DomainSuffixes))
		for _, d := range r.DomainSuffixes {
			if name := normalizeHost(d); name != "" {
				out.suffixes[name] = struct{}{}
				out.hasDest = true
			}
		}
	}

	if len(r.Ports) > 0 {
		ranges, err := compilePorts(r.Ports)
		if err != nil {
			return rule{}, fmt.Errorf("rule %s: %w", origin, err)
		}
		out.ports = ranges
	}

	for _, p := range r.Protocols {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "tcp":
			out.tcp, out.hasProto = true, true
		case "udp":
			out.udp, out.hasProto = true, true
		}
	}
	return out, nil
}

func compilePorts(values []string) ([]portRange, error) {
	ranges := make([]portRange, 0, len(values))
	for _, raw := range values {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			continue
		}
		lo, hi, found := strings.Cut(spec, "-")
		low, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		high := low
		if found {
			if high, err = parsePort(hi); err != nil {
				return nil, err
			}
		}
		if low > high {
			return nil, fmt.Errorf("port range %q starts above its end", spec)
		}
		ranges = append(ranges, portRange{lo: low, hi: high})
	}
	// matchPort binary-searches on hi, so the ranges must be sorted and
	// non-overlapping — merge adjacent entries after sorting.
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].lo != ranges[j].lo {
			return ranges[i].lo < ranges[j].lo
		}
		return ranges[i].hi < ranges[j].hi
	})
	merged := ranges[:0]
	for _, r := range ranges {
		if n := len(merged); n > 0 && r.lo <= merged[n-1].hi+1 {
			if r.hi > merged[n-1].hi {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged, nil
}

func parsePort(raw string) (uint16, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return uint16(port), nil
}

// normalizeGroupIDs drops unknown and duplicate references and sorts what is
// left, so two users with the same groups in a different order share one
// interned policy.
func normalizeGroupIDs(ids []string, groups map[string]*compiledGroup) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := groups[id]; !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// buildPolicy flattens the user's groups into one ordered rule list.
//
// Flattening at update time rather than at match time is what makes the
// check cost independent of how many groups a user belongs to.
func buildPolicy(ids []string, groups map[string]*compiledGroup, nodeDefault Action, dnsAllowed, dryRun bool) *Policy {
	ordered := make([]*compiledGroup, 0, len(ids))
	for _, id := range ids {
		if g, ok := groups[id]; ok {
			ordered = append(ordered, g)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].priority != ordered[j].priority {
			return ordered[i].priority < ordered[j].priority
		}
		return ordered[i].id < ordered[j].id
	})

	def := nodeDefault
	for _, g := range ordered {
		if g.hasDef {
			def = g.def
			break
		}
	}

	var rules []rule
	// Under a deny default, name resolution has to survive or the node is
	// indistinguishable from a dead one. This goes in front of everything so
	// no group rule can accidentally strand a user without DNS.
	if def == ActionDeny && dnsAllowed {
		rules = append(rules, rule{
			action:   ActionAllow,
			ports:    []portRange{{lo: 53, hi: 53}},
			origin:   "implicit-dns",
			hasProto: false,
		})
	}
	for _, g := range ordered {
		rules = append(rules, g.rules...)
	}

	if len(rules) == 0 && def == ActionAllow {
		return allowAll
	}
	return &Policy{rules: rules, def: def, dryRun: dryRun}
}

func parseMode(cfg *model.ACLConfig) Mode {
	if cfg == nil {
		return ModeOff
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "enforce":
		return ModeEnforce
	case "dryrun":
		return ModeDryRun
	default:
		return ModeOff
	}
}

func parseAction(value string) Action {
	if strings.EqualFold(strings.TrimSpace(value), "deny") {
		return ActionDeny
	}
	return ActionAllow
}

func normalizeHost(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}
