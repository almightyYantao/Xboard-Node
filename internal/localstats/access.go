package localstats

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
)

// Access aggregation: the access records the kernel buffers for the panel
// are also folded into small per-destination counters here. Only aggregates
// are kept (never individual records), in two generations that rotate every
// accessGenSpan, so the numbers cover the last 12–24 hours. Every map is
// capped; when one overflows, the smaller half is dropped (top lists stay
// right, totals for the long tail become approximate).
const (
	accessGenSpan = 12 * time.Hour
	maxHosts      = 2048 // destinations per generation
	maxUsers      = 500  // users with per-destination detail per generation
	maxUserHosts  = 40   // destinations per user per generation
	maxHostLen    = 253
)

// HostStat is one destination (domain, or IP when there was no domain).
type HostStat struct {
	Host  string `json:"host"`
	Bytes int64  `json:"bytes"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	Count int64  `json:"count"` // connections
	Fails int64  `json:"fails"` // connections whose outbound dial failed
}

func (h *HostStat) add(o HostStat) {
	h.Bytes += o.Bytes
	h.Up += o.Up
	h.Down += o.Down
	h.Count += o.Count
	h.Fails += o.Fails
}

type accessGen struct {
	start   time.Time
	records int64
	hosts   map[string]*HostStat
	users   map[int]map[string]*HostStat
}

func newGen(t time.Time) *accessGen {
	return &accessGen{start: t, hosts: map[string]*HostStat{}, users: map[int]map[string]*HostStat{}}
}

type accessAgg struct {
	mu        sync.Mutex
	cur, prev *accessGen
}

func newAccessAgg() *accessAgg { return &accessAgg{} }

// AddAccess folds access records into the local aggregates. It does not
// modify or keep the records; callers keep using them as before. No-op when
// the endpoint is disabled.
func AddAccess(recs []model.AccessRecord) {
	if len(recs) == 0 || !Enabled() {
		return
	}
	eng.access.add(time.Now(), recs)
}

func (a *accessAgg) rotate(now time.Time) {
	if a.cur == nil {
		a.cur = newGen(now)
		return
	}
	if now.Sub(a.cur.start) >= accessGenSpan {
		a.prev, a.cur = a.cur, newGen(now)
		if a.prev != nil && now.Sub(a.prev.start) >= 2*accessGenSpan {
			a.prev = nil // idle for a long time: the old generation is stale
		}
	}
}

func hostKey(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if len(h) > maxHostLen {
		h = h[:maxHostLen]
	}
	return h
}

func (a *accessAgg) add(now time.Time, recs []model.AccessRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rotate(now)
	g := a.cur
	for i := range recs {
		r := &recs[i]
		if r.IsACL() || r.DestHost == "" {
			continue
		}
		st := HostStat{Bytes: r.Upload + r.Download, Up: r.Upload, Down: r.Download, Count: 1}
		if r.Reason != "" {
			st.Fails = 1
		}
		k := hostKey(r.DestHost)
		g.records++
		h := g.hosts[k]
		if h == nil {
			h = &HostStat{Host: k}
			g.hosts[k] = h
		}
		h.add(st)
		um := g.users[r.UserID]
		if um == nil {
			um = map[string]*HostStat{}
			g.users[r.UserID] = um
		}
		uh := um[k]
		if uh == nil {
			uh = &HostStat{Host: k}
			um[k] = uh
		}
		uh.add(st)
		if len(um) > maxUserHosts {
			pruneHosts(um, maxUserHosts/2)
		}
	}
	if len(g.hosts) > maxHosts {
		pruneHosts(g.hosts, maxHosts/2)
	}
	if len(g.users) > maxUsers {
		pruneUsers(g.users, maxUsers/2)
	}
}

func rank(a, b *HostStat) bool {
	if a.Bytes != b.Bytes {
		return a.Bytes > b.Bytes
	}
	if a.Count != b.Count {
		return a.Count > b.Count
	}
	return a.Host < b.Host
}

// pruneHosts keeps the keep largest entries (by traffic, then connections).
func pruneHosts(m map[string]*HostStat, keep int) {
	l := make([]*HostStat, 0, len(m))
	for _, h := range m {
		l = append(l, h)
	}
	sort.Slice(l, func(i, j int) bool { return rank(l[i], l[j]) })
	for _, h := range l[keep:] {
		delete(m, h.Host)
	}
}

func pruneUsers(m map[int]map[string]*HostStat, keep int) {
	type kv struct {
		uid   int
		bytes int64
	}
	l := make([]kv, 0, len(m))
	for uid, hs := range m {
		var b int64
		for _, h := range hs {
			b += h.Bytes
		}
		l = append(l, kv{uid, b})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].bytes != l[j].bytes {
			return l[i].bytes > l[j].bytes
		}
		return l[i].uid < l[j].uid
	})
	for _, x := range l[keep:] {
		delete(m, x.uid)
	}
}

// merged returns the destinations of both generations (and their start).
func (a *accessAgg) merged(pick func(g *accessGen) map[string]*HostStat) (map[string]*HostStat, int64, int64) {
	out := map[string]*HostStat{}
	var since, records int64
	for _, g := range []*accessGen{a.prev, a.cur} {
		if g == nil {
			continue
		}
		if since == 0 {
			since = g.start.Unix()
		}
		records += g.records
		for k, h := range pick(g) {
			x := out[k]
			if x == nil {
				x = &HostStat{Host: k}
				out[k] = x
			}
			x.add(*h)
		}
	}
	return out, since, records
}

func top(m map[string]*HostStat, n int, less func(a, b *HostStat) bool) []HostStat {
	l := make([]*HostStat, 0, len(m))
	for _, h := range m {
		l = append(l, h)
	}
	sort.Slice(l, func(i, j int) bool { return less(l[i], l[j]) })
	if len(l) > n {
		l = l[:n]
	}
	out := make([]HostStat, len(l))
	for i, h := range l {
		out[i] = *h
	}
	return out
}

func byCount(a, b *HostStat) bool {
	if a.Count != b.Count {
		return a.Count > b.Count
	}
	return rank(a, b)
}

// AccessOut is the access section of /stats.
type AccessOut struct {
	Enabled bool       `json:"enabled"` // the panel has access logging on for at least one node
	Since   int64      `json:"since"`   // start of the aggregation window (0 = nothing yet)
	Records int64      `json:"records"` // connections aggregated
	ByBytes []HostStat `json:"by_bytes"`
	ByCount []HostStat `json:"by_count"`
}

func (a *accessAgg) report(now time.Time, enabled bool, n int) AccessOut {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rotate(now)
	m, since, records := a.merged(func(g *accessGen) map[string]*HostStat { return g.hosts })
	return AccessOut{Enabled: enabled, Since: since, Records: records, ByBytes: top(m, n, rank), ByCount: top(m, n, byCount)}
}

func (a *accessAgg) user(uid, n int) (int64, []HostStat) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m, since, _ := a.merged(func(g *accessGen) map[string]*HostStat { return g.users[uid] })
	return since, top(m, n, rank)
}
