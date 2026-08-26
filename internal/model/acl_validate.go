package model

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Limits mirror docs-user-acl.md §4. They exist so a mistaken panel push
// (or a compromised one) cannot make the node spend unbounded memory
// compiling policies.
const (
	maxACLCIDRsPerGroup = 20000
	maxACLCIDRsTotal    = 200000
)

var aclGroupIDRe = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// ValidateACLConfig checks a panel-pushed ACL policy.
//
// The node validates independently of the panel because a rejected rule here
// is only visible in node logs — operators see nothing. Anything this
// function rejects should have been rejected at the panel with a message the
// operator can read.
func ValidateACLConfig(cfg *ACLConfig) error {
	if cfg == nil {
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "", "off", "dryrun", "enforce":
	default:
		return fmt.Errorf("acl.mode %q is not supported (want off, dryrun, or enforce)", cfg.Mode)
	}

	if _, err := parseACLAction(cfg.DefaultAction, "acl.default_action"); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(cfg.Groups))
	total := 0

	for i, group := range cfg.Groups {
		id := strings.TrimSpace(group.ID)
		if !aclGroupIDRe.MatchString(id) {
			return fmt.Errorf("acl.groups[%d].id %q must match %s", i, group.ID, aclGroupIDRe)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("acl.groups[%d].id %q is duplicated", i, id)
		}
		seen[id] = struct{}{}

		if strings.TrimSpace(group.DefaultAction) != "" {
			if _, err := parseACLAction(group.DefaultAction,
				fmt.Sprintf("acl.groups[%d].default_action", i)); err != nil {
				return err
			}
		}

		groupCIDRs := 0
		for j, r := range group.Rules {
			path := fmt.Sprintf("acl.groups[%d].rules[%d]", i, j)

			if _, err := parseACLAction(r.Action, path+".action"); err != nil {
				return err
			}
			if strings.TrimSpace(r.Action) == "" {
				return fmt.Errorf("%s.action is required", path)
			}

			// A rule with no matcher at all matches unconditionally. That is
			// almost always a half-finished edit, not an intent to write a
			// catch-all, so refuse it rather than silently shadowing
			// everything below it.
			if !hasACLMatch(r) {
				return fmt.Errorf("%s requires at least one match condition", path)
			}

			allowRule := strings.EqualFold(strings.TrimSpace(r.Action), "allow")
			for k, entry := range r.IPCIDRs {
				prefix, err := parseACLCIDR(entry)
				if err != nil {
					return fmt.Errorf("%s.ip_cidrs[%d]: %w", path, k, err)
				}
				// Loopback is the node itself and link-local carries cloud
				// metadata (169.254.169.254 hands out credentials). Neither
				// may be opened to a VPN user, so an allow rule naming them
				// is rejected outright rather than filtered — the same
				// stance sanitizePrivateAllow takes for node-wide routes.
				if allowRule && isForbiddenACLTarget(prefix) {
					return fmt.Errorf("%s.ip_cidrs[%d]: refusing to allow %q (loopback / link-local / unspecified)",
						path, k, entry)
				}
			}
			groupCIDRs += len(r.IPCIDRs)

			for k, entry := range r.Domains {
				if err := validateACLDomain(entry); err != nil {
					return fmt.Errorf("%s.domains[%d]: %w", path, k, err)
				}
			}
			for k, entry := range r.DomainSuffixes {
				if err := validateACLDomain(entry); err != nil {
					return fmt.Errorf("%s.domain_suffixes[%d]: %w", path, k, err)
				}
			}
			if err := validateACLPorts(r.Ports, path+".ports"); err != nil {
				return err
			}
			for k, entry := range r.Protocols {
				switch strings.ToLower(strings.TrimSpace(entry)) {
				case "tcp", "udp":
				default:
					return fmt.Errorf("%s.protocols[%d] %q must be tcp or udp", path, k, entry)
				}
			}
		}

		if groupCIDRs > maxACLCIDRsPerGroup {
			return fmt.Errorf("acl.groups[%d] has %d CIDRs, limit is %d — split the group",
				i, groupCIDRs, maxACLCIDRsPerGroup)
		}
		total += groupCIDRs
	}

	if total > maxACLCIDRsTotal {
		return fmt.Errorf("acl has %d CIDRs across all groups, limit is %d", total, maxACLCIDRsTotal)
	}
	return nil
}

func parseACLAction(value, path string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(value)); v {
	case "", "allow", "deny":
		return v, nil
	default:
		return "", fmt.Errorf("%s %q must be allow or deny", path, value)
	}
}

func hasACLMatch(r ACLRule) bool {
	return len(r.IPCIDRs) > 0 || len(r.Domains) > 0 || len(r.DomainSuffixes) > 0 ||
		len(r.Ports) > 0 || len(r.Protocols) > 0
}

// parseACLCIDR accepts a prefix with host bits set (10.0.0.1/8) and returns
// the masked form, matching what net.ParseCIDR does for the node's existing
// route handling.
func parseACLCIDR(entry string) (netip.Prefix, error) {
	trimmed := strings.TrimSpace(entry)
	if trimmed == "" {
		return netip.Prefix{}, fmt.Errorf("empty CIDR")
	}
	prefix, err := netip.ParsePrefix(trimmed)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", entry)
	}
	return prefix.Masked(), nil
}

// forbiddenACLPrefixes must never be reachable through a node: loopback is
// the agent itself (its admin ports would be exposed to every VPN user) and
// link-local carries cloud metadata, where 169.254.169.254 hands out
// credentials.
var forbiddenACLPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
}

// isForbiddenACLTarget reports whether prefix lies entirely inside a
// forbidden range.
//
// Containment, not overlap, is the test on purpose. Overlap would reject
// 0.0.0.0/0, but a prefix that broad is a deliberate "allow everything"
// rather than an attempt to reach loopback — the panel warns about it
// instead (docs-user-acl.md §4). Only a prefix that names forbidden space
// specifically is refused.
func isForbiddenACLTarget(prefix netip.Prefix) bool {
	addr := prefix.Addr()
	for _, forbidden := range forbiddenACLPrefixes {
		if forbidden.Addr().Is4() != addr.Is4() {
			continue
		}
		if prefix.Bits() >= forbidden.Bits() && forbidden.Contains(addr) {
			return true
		}
	}
	return false
}

func validateACLDomain(entry string) error {
	name := strings.TrimSpace(entry)
	if name == "" {
		return fmt.Errorf("empty domain")
	}
	if strings.ContainsAny(name, " \t/\\?#@:") {
		return fmt.Errorf("invalid domain %q (no scheme, path, port, or spaces)", entry)
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("invalid domain %q (no leading or trailing dot)", entry)
	}
	return nil
}

func validateACLPorts(values []string, path string) error {
	for i, raw := range values {
		lo, hi, err := parseACLPortSpec(raw)
		if err != nil {
			return fmt.Errorf("%s[%d]: %w", path, i, err)
		}
		if lo > hi {
			return fmt.Errorf("%s[%d]: range %q starts above its end", path, i, raw)
		}
	}
	return nil
}

// parseACLPortSpec parses "443" or "8000-9000".
func parseACLPortSpec(raw string) (uint16, uint16, error) {
	spec := strings.TrimSpace(raw)
	if spec == "" {
		return 0, 0, fmt.Errorf("empty port")
	}
	lo, hi, found := strings.Cut(spec, "-")
	if !found {
		port, err := parseACLPort(spec)
		return port, port, err
	}
	low, err := parseACLPort(lo)
	if err != nil {
		return 0, 0, err
	}
	high, err := parseACLPort(hi)
	if err != nil {
		return 0, 0, err
	}
	return low, high, nil
}

func parseACLPort(raw string) (uint16, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q (want 1-65535)", raw)
	}
	return uint16(port), nil
}
