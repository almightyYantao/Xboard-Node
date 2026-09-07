package main

// `xbctl acl eval` answers the question a rule list cannot be eyeballed for:
// given this pushed ACL config, what verdict does this user get for this
// target, and which rule decided it.
//
// It runs the node's own evaluator (internal/acl), not a reimplementation, so
// a semantics change cannot make the tool and the node disagree. That matters
// because the two things people get wrong here — domain rules outranking
// ip_cidr rules, and a rule that never matches because the node never resolved
// the name — are both invisible in the JSON.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cedar2025/xboard-node/internal/acl"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func runACL(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printACLUsage()
		return nil
	}
	if args[0] != "eval" {
		return fmt.Errorf("usage: xbctl acl eval --config <path|-> [flags] <target>...")
	}
	return runACLEval(args[1:])
}

func printACLUsage() {
	fmt.Println(`xbctl acl eval --config <path|-> [flags] <target>...

  Evaluate a pushed ACL config against concrete targets, using the node's own
  evaluator. Prints the verdict and the rule that decided it.

flags:
  --config <path|->   NodeConfig JSON (what GET /api/v2/server/config returns),
                      or a bare "acl" object. "-" reads stdin.
  --users <path|->    User list JSON (GET .../user), for --user lookups.
  --user <uuid>       Evaluate as this user, taking its acl_groups from --users.
  --groups a,b        Evaluate as a synthetic user in these groups instead.
  --json              Emit results as JSON.

target:
  host                    domain target the node did not resolve
  host@ip[,ip...]         domain target plus the addresses the node resolved
  ip                      IP-addressed target
  port defaults to 443 and rides either side: host:8080@10.0.0.1 or
  host@10.0.0.1:8080; an IPv6 literal with a port must be bracketed,
  [2001:db8::1]:443. Append /udp to evaluate as UDP (default tcp).

examples:
  curl -s -H "Authorization: Bearer $TOKEN" "$PANEL/api/v2/server/config?machine_id=4" \
    | xbctl acl eval --config - --groups acl-8 \
        moon.corp.example.com@10.0.0.1 okr.corp.example.com@10.0.0.50 10.10.99.166:7680

  xbctl acl eval --config cfg.json --users users.json \
    --user 28d860d7-ff89-4dc5-bb21-930627bcb0a7 moon.corp.example.com@10.0.0.1`)
}

type aclEvalOpts struct {
	configPath string
	usersPath  string
	user       string
	groups     string
	asJSON     bool
	targets    []string
}

func parseACLEvalArgs(args []string) (aclEvalOpts, error) {
	var o aclEvalOpts
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config", "--users", "--user", "--groups":
			flag := args[i]
			i++
			if i >= len(args) {
				return o, fmt.Errorf("%s requires a value", flag)
			}
			switch flag {
			case "--config":
				o.configPath = args[i]
			case "--users":
				o.usersPath = args[i]
			case "--user":
				o.user = args[i]
			case "--groups":
				o.groups = args[i]
			}
		case "--json":
			o.asJSON = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return o, fmt.Errorf("unknown flag: %s", args[i])
			}
			o.targets = append(o.targets, args[i])
		}
	}
	if o.configPath == "" {
		return o, errors.New("--config is required (use - for stdin)")
	}
	if len(o.targets) == 0 {
		return o, errors.New("no targets given")
	}
	if o.groups == "" && o.user == "" {
		return o, errors.New("need --groups or --user")
	}
	if o.user != "" && o.usersPath == "" {
		return o, errors.New("--user needs --users to look up its acl_groups")
	}
	return o, nil
}

// aclEvalConfig picks only the two fields that matter out of a NodeConfig.
// Decoding the whole struct would couple this tool to every unrelated protocol
// field a panel might send.
type aclEvalConfig struct {
	ACL               *panel.ACLConfig `json:"acl"`
	ACLResolveDomains []string         `json:"acl_resolve_domains"`
}

type aclEvalUserList struct {
	Users []struct {
		ID        int      `json:"id"`
		UUID      string   `json:"uuid"`
		ACLGroups []string `json:"acl_groups"`
	} `json:"users"`
}

type aclEvalResult struct {
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Proto    string `json:"proto"`
	Verdict  string `json:"verdict"`
	Rule     string `json:"rule"`
	Enforced bool   `json:"enforced"`
	Note     string `json:"note,omitempty"`
}

func runACLEval(args []string) error {
	o, err := parseACLEvalArgs(args)
	if err != nil {
		return err
	}

	cfg, err := loadACLEvalConfig(o.configPath)
	if err != nil {
		return err
	}
	if cfg.ACL == nil {
		return errors.New("no acl in config — the panel pushed nothing, so ACL is disabled entirely")
	}

	users, uuid, err := aclEvalUsers(o)
	if err != nil {
		return err
	}

	// Reuse the node's own panel→model conversion so a field the tool forgets
	// to carry over cannot make it disagree with the node.
	spec := model.NodeSpecFromPanel(&panel.NodeConfig{
		ACL:               cfg.ACL,
		ACLResolveDomains: cfg.ACLResolveDomains,
	})

	// The store logs a summary line on every recompile. Useful on a node,
	// noise in a one-shot report — and it would land in the middle of piped
	// JSON output.
	nlog.Init(io.Discard, slog.LevelError, false)

	store := acl.New()
	if err := store.Update(spec.ACL, users); err != nil {
		return fmt.Errorf("the node would reject this config: %w", err)
	}
	policy := store.Lookup(uuid)

	results := make([]aclEvalResult, 0, len(o.targets))
	for _, raw := range o.targets {
		dest, label, err := parseACLTarget(raw)
		if err != nil {
			return err
		}
		action, origin := policy.Evaluate(dest)
		proto := "tcp"
		if dest.UDP {
			proto = "udp"
		}
		results = append(results, aclEvalResult{
			Target:   label,
			Port:     dest.Port,
			Proto:    proto,
			Verdict:  action.String(),
			Rule:     origin,
			Enforced: action == acl.ActionDeny && !policy.DryRun(),
			Note:     resolveCoverageNote(dest, spec.ACLResolveDomains),
		})
	}

	if o.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"mode":       spec.ACL.Mode,
			"default":    spec.ACL.DefaultAction,
			"user":       uuid,
			"acl_groups": aclGroupsOf(users, uuid),
			"restricted": policy.Restricted(),
			"results":    results,
		})
	}
	printACLEvalResults(spec, policy, users, uuid, results)
	return nil
}

func loadACLEvalConfig(path string) (aclEvalConfig, error) {
	var out aclEvalConfig
	data, err := readFileOrStdin(path)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("parse %s: %w", path, err)
	}
	if out.ACL != nil {
		return out, nil
	}
	// Also accept a bare acl object, so `jq .acl` output works as input.
	var bare panel.ACLConfig
	if err := json.Unmarshal(data, &bare); err == nil && (bare.Mode != "" || len(bare.Groups) > 0) {
		out.ACL = &bare
	}
	return out, nil
}

func aclEvalUsers(o aclEvalOpts) ([]model.UserSpec, string, error) {
	if o.groups != "" {
		const uuid = "acl-eval"
		return []model.UserSpec{{ID: 1, UUID: uuid, ACLGroups: splitACLGroups(o.groups)}}, uuid, nil
	}

	data, err := readFileOrStdin(o.usersPath)
	if err != nil {
		return nil, "", err
	}
	var list aclEvalUserList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", o.usersPath, err)
	}

	users := make([]model.UserSpec, 0, len(list.Users))
	found := false
	for _, u := range list.Users {
		users = append(users, model.UserSpec{ID: u.ID, UUID: u.UUID, ACLGroups: u.ACLGroups})
		if u.UUID == o.user {
			found = true
		}
	}
	if !found {
		return nil, "", fmt.Errorf("user %s not in %s (%d users listed)", o.user, o.usersPath, len(users))
	}
	return users, o.user, nil
}

func readFileOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

func splitACLGroups(s string) []string {
	out := make([]string, 0, 2)
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func aclGroupsOf(users []model.UserSpec, uuid string) []string {
	for _, u := range users {
		if u.UUID == uuid {
			return u.ACLGroups
		}
	}
	return nil
}

// parseACLTarget accepts host[:port]@ip[,ip...], ip[:port], or [v6]:port,
// with an optional /tcp or /udp suffix.
//
// Splitting on "@" before touching the port is what keeps IPv6 working: a bare
// v6 literal is full of colons, so "last colon is the port" would eat its last
// label. A v6 address carrying a port has to be bracketed, as everywhere else.
func parseACLTarget(raw string) (acl.Dest, string, error) {
	spec := strings.TrimSpace(raw)
	dest := acl.Dest{Port: 443}

	if rest, ok := strings.CutSuffix(spec, "/udp"); ok {
		dest.UDP = true
		spec = rest
	} else if rest, ok := strings.CutSuffix(spec, "/tcp"); ok {
		spec = rest
	}

	hostSpec, addrSpec, hasAddrs := strings.Cut(spec, "@")
	host, port, hasPort := splitACLPort(strings.TrimSpace(hostSpec))
	if hasPort {
		dest.Port = port
	}
	host = strings.ToLower(host)
	if host == "" {
		return dest, "", fmt.Errorf("target %q has no host", raw)
	}

	if !hasAddrs {
		if ip, err := netip.ParseAddr(host); err == nil {
			dest.IP = ip.Unmap()
			return dest, host, nil
		}
		if strings.Contains(host, ":") {
			return dest, "", fmt.Errorf("target %q: bracket an IPv6 address that carries a port, e.g. [2001:db8::1]:443", raw)
		}
		dest.Domain = host
		return dest, host, nil
	}

	dest.Domain = host
	labels := make([]string, 0, 2)
	for _, part := range strings.Split(addrSpec, ",") {
		// A port trailing the address list is the natural way to write an IPv4
		// target, so accept it there too; v6 elements keep their colons.
		entry, p, ok := splitACLPort(strings.TrimSpace(part))
		if entry == "" {
			continue
		}
		if ok {
			dest.Port = p
		}
		ip, err := netip.ParseAddr(entry)
		if err != nil {
			return dest, "", fmt.Errorf("target %q: invalid address %q", raw, entry)
		}
		dest.ResolvedIPs = append(dest.ResolvedIPs, ip.Unmap())
		labels = append(labels, entry)
	}
	if len(dest.ResolvedIPs) == 0 {
		return dest, "", fmt.Errorf("target %q has @ but no addresses", raw)
	}
	return dest, host + " → " + strings.Join(labels, ","), nil
}

// splitACLPort peels a trailing :port off a host or address.
//
// A bare IPv6 literal is returned untouched: it parses as an address, and a
// hostname or IPv4 address can hold at most one colon, so anything with more
// is a v6 literal that must be bracketed to carry a port.
func splitACLPort(s string) (string, uint16, bool) {
	if s == "" {
		return "", 0, false
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			inner := s[1:end]
			rest := s[end+1:]
			if after, ok := strings.CutPrefix(rest, ":"); ok {
				if port, err := strconv.ParseUint(after, 10, 16); err == nil {
					return inner, uint16(port), true
				}
			}
			return inner, 0, false
		}
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return s, 0, false
	}
	if strings.Count(s, ":") != 1 {
		return s, 0, false
	}
	host, portStr, _ := strings.Cut(s, ":")
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return s, 0, false
	}
	return host, uint16(port), true
}

// resolveCoverageNote catches the mismatch that makes an eval lie: addresses
// supplied for a name the node would never resolve, or a name the node *would*
// resolve evaluated with no addresses at all. Either way the verdict printed
// is not the verdict production would produce.
func resolveCoverageNote(dest acl.Dest, resolveDomains []string) string {
	if dest.Domain == "" {
		return ""
	}
	covered := aclSuffixCovers(resolveDomains, dest.Domain)
	switch {
	case len(dest.ResolvedIPs) > 0 && !covered:
		return "not in acl_resolve_domains: the node would have no addresses here, ip_cidrs cannot apply"
	case len(dest.ResolvedIPs) == 0 && covered:
		return "in acl_resolve_domains: the node would resolve this, pass @<ip> to see the real verdict"
	}
	return ""
}

// aclSuffixCovers mirrors acl.matchSuffix: equality, or a match on a label
// boundary, so "corp.example.com" covers "a.corp.example.com" but not
// "notcorp.example.com".
func aclSuffixCovers(suffixes []string, host string) bool {
	for _, raw := range suffixes {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func printACLEvalResults(spec *model.NodeSpec, policy *acl.Policy, users []model.UserSpec, uuid string, results []aclEvalResult) {
	groups := aclGroupsOf(users, uuid)
	if len(groups) == 0 {
		groups = []string{"(none)"}
	}
	fmt.Printf("mode=%s default=%s groups=%d  user=%s acl_groups=[%s]\n",
		spec.ACL.Mode, spec.ACL.DefaultAction, len(spec.ACL.Groups), uuid, strings.Join(groups, ","))
	if len(spec.ACLResolveDomains) > 0 {
		fmt.Printf("acl_resolve_domains: %s\n", strings.Join(spec.ACLResolveDomains, ", "))
	}
	if !policy.Restricted() {
		fmt.Println("note: this user's policy can never deny anything (allow default, no rules)")
	}
	if policy.DryRun() {
		fmt.Println("note: mode is dryrun — denials are logged and the connection still goes through")
	}
	fmt.Println()

	width := len("TARGET")
	for _, r := range results {
		if len(r.Target) > width {
			width = len(r.Target)
		}
	}
	fmt.Printf("%-*s  %-5s  %-5s  %-7s  %s\n", width, "TARGET", "PORT", "PROTO", "VERDICT", "RULE")
	for _, r := range results {
		fmt.Printf("%-*s  %-5d  %-5s  %-7s  %s\n", width, r.Target, r.Port, r.Proto, r.Verdict, r.Rule)
	}

	notes := map[string][]string{}
	for _, r := range results {
		if r.Note != "" {
			notes[r.Note] = append(notes[r.Note], r.Target)
		}
	}
	if len(notes) == 0 {
		return
	}
	keys := make([]string, 0, len(notes))
	for k := range notes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println()
	for _, k := range keys {
		fmt.Printf("! %s\n  %s\n", k, strings.Join(notes[k], ", "))
	}
}
