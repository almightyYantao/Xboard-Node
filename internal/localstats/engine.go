package localstats

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Limits: everything the engine keeps is bounded.
const (
	historyLen     = 90  // 15 min of 10 s points
	maxUsersOut    = 500 // users listed in /stats
	maxIPsOut      = 32  // source IPs listed per user
	alertWindow    = 10 * time.Minute
	idleForget     = time.Hour // forget per-user detector state after this long idle
	sharedSamples  = 3         // online IPs above the limit this many samples in a row
	sharedRejects  = 5         // or this many device-limit refusals within alertWindow
	surgeMinBps    = 4 << 20   // short-term average must exceed 4 MiB/s (≈ 33 Mbps)
	surgeFactor    = 5         // … and be this many times the long-term baseline
	surgeClear     = 3         // clears below this factor (hysteresis)
	surgeWarmup    = 30        // samples (5 min) before a user can be flagged
	surgeShortSecs = 300       // short EWMA ~5 min
	surgeLongSecs  = 3600      // baseline EWMA ~1 h
	dialMinFails   = 30        // dial failures within alertWindow
	dialMinRatio   = 0.2       // … and at least this share of attempts
)

// Alert is a condition worth showing to the operator.
//
//	shared: user's online IPs exceed the device limit, or connections are being
//	        refused by the device limit (value = online IPs, limit = device limit,
//	        rejects = refusals in the last 10 min)
//	surge:  user's 5-min average rate jumped (value = bytes/s, limit = baseline bytes/s)
//	dial:   many outbound dial failures on a node (value = failures, limit = attempts,
//	        both over the last 10 min)
type Alert struct {
	Kind    string `json:"kind"`
	User    int    `json:"user,omitempty"`
	Node    int    `json:"node,omitempty"`
	Value   int64  `json:"value"`
	Limit   int64  `json:"limit"`
	Rejects int64  `json:"rejects,omitempty"`
	Since   int64  `json:"since"`
}

type userAgg struct {
	up, down     int64 // bytes/s
	totUp        int64 // cumulative since the trackers started
	totDown      int64
	ips          map[string]bool
	conns        int
	limit        int
	uuid         string
	nodes        []int
	rejIPs       []string
	rejectWindow int64
}

type surgeState struct {
	short, long float64
	n           int
	on          bool
	since       int64
	lastActive  time.Time
}

type sharedState struct {
	over  int
	since int64
}

type event struct {
	t time.Time
	n int64
}

type dialState struct {
	epoch        time.Time
	total, fails uint64
	events       []dialEvent
}

type dialEvent struct {
	t            time.Time
	total, fails int64
}

type rejKey struct{ node, uid int }

type engine struct {
	mu       sync.Mutex
	sampled  time.Time
	views    []NodeView
	machines []MachineView
	users    map[int]*userAgg
	history  [][6]int64 // t, up bps, down bps, conns, online users, online IPs

	surge    map[int]*surgeState
	shared   map[int]*sharedState
	rejPrev  map[rejKey]uint64
	rejEpoch map[int]time.Time
	rejEv    map[int][]event
	dial     map[int]*dialState
	alerts   []Alert

	access *accessAgg
}

func newEngine() *engine {
	return &engine{
		users:    map[int]*userAgg{},
		surge:    map[int]*surgeState{},
		shared:   map[int]*sharedState{},
		rejPrev:  map[rejKey]uint64{},
		rejEpoch: map[int]time.Time{},
		rejEv:    map[int][]event{},
		dial:     map[int]*dialState{},
		access:   newAccessAgg(),
	}
}

func (e *engine) run(ctx context.Context) {
	t := time.NewTicker(SampleInterval)
	defer t.Stop()
	e.sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.sample()
		}
	}
}

// sample collects views outside the engine lock (it calls into services).
func (e *engine) sample() {
	ns, ms := sources()
	views := make([]NodeView, 0, len(ns))
	for _, s := range ns {
		views = append(views, s.StatsView())
	}
	machines := make([]MachineView, 0, len(ms))
	for _, m := range ms {
		machines = append(machines, m.StatsMachineView())
	}
	e.step(time.Now(), views, machines)
}

func interval(v NodeView) int64 {
	if v.TrackInterval > 0 {
		return int64(v.TrackInterval)
	}
	return 10
}

// step derives aggregates, history and alerts from one round of views.
func (e *engine) step(now time.Time, views []NodeView, machines []MachineView) {
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })

	users := map[int]*userAgg{}
	get := func(uid int) *userAgg {
		u := users[uid]
		if u == nil {
			u = &userAgg{ips: map[string]bool{}}
			users[uid] = u
		}
		return u
	}
	var upAll, downAll, connsAll int64
	for _, v := range views {
		iv := interval(v)
		tv := v.Tracker
		if v.Running {
			upAll += tv.OutCycle / iv
			downAll += tv.InCycle / iv
			connsAll += int64(tv.ConnCount)
			for uid, d := range tv.UserSpeed {
				u := get(uid)
				u.up += d[0] / iv
				u.down += d[1] / iv
			}
			for uid, ips := range tv.AliveIPs {
				if len(ips) == 0 {
					continue
				}
				u := get(uid)
				for ip := range ips {
					u.ips[ip] = true
				}
			}
			for uid, c := range v.UserConns {
				if c > 0 {
					get(uid).conns += c
				}
			}
		}
		for uid, t := range tv.Totals {
			if u := users[uid]; u != nil {
				u.totUp += t[0]
				u.totDown += t[1]
			}
		}
		for uid, r := range v.Rejects {
			if len(r.IPs) > 0 {
				get(uid).rejIPs = append(get(uid).rejIPs, r.IPs...)
			}
		}
	}
	for uid, u := range users {
		for _, v := range views {
			if m, ok := v.Users[uid]; ok {
				if u.uuid == "" {
					u.uuid = m.UUID
				}
				if m.DeviceLimit > u.limit {
					u.limit = m.DeviceLimit
				}
			}
			if _, ok := v.Tracker.AliveIPs[uid]; ok {
				u.nodes = append(u.nodes, v.ID)
			} else if _, ok := v.Tracker.UserSpeed[uid]; ok {
				u.nodes = append(u.nodes, v.ID)
			}
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.sampled, e.views, e.machines, e.users = now, views, machines, users

	var onlineUsers, onlineIPs int64
	for _, u := range users {
		if len(u.ips) > 0 {
			onlineUsers++
			onlineIPs += int64(len(u.ips))
		}
	}
	e.history = append(e.history, [6]int64{now.Unix(), upAll, downAll, connsAll, onlineUsers, onlineIPs})
	if len(e.history) > historyLen {
		e.history = append(e.history[:0:0], e.history[len(e.history)-historyLen:]...)
	}

	e.stepRejects(now, views, users)
	e.stepShared(now, users)
	e.stepSurge(now, users)
	e.stepDial(now, views)
	e.buildAlerts()
}

func (e *engine) stepRejects(now time.Time, views []NodeView, users map[int]*userAgg) {
	cut := now.Add(-alertWindow)
	for _, v := range views {
		// A new kernel run starts counting from zero: a smaller count is a reset.
		for uid, r := range v.Rejects {
			k := rejKey{v.ID, uid}
			prev, seen := e.rejPrev[k]
			d := int64(r.Count)
			if seen && r.Count >= prev {
				d = int64(r.Count - prev)
			}
			e.rejPrev[k] = r.Count
			if d > 0 {
				e.rejEv[uid] = append(e.rejEv[uid], event{now, d})
			}
		}
	}
	for uid, evs := range e.rejEv {
		i := 0
		for i < len(evs) && evs[i].t.Before(cut) {
			i++
		}
		evs = evs[i:]
		if len(evs) == 0 {
			delete(e.rejEv, uid)
			continue
		}
		e.rejEv[uid] = evs
		var n int64
		for _, ev := range evs {
			n += ev.n
		}
		if u := users[uid]; u != nil {
			u.rejectWindow = n
		}
	}
	if len(e.rejPrev) > 20000 { // users churned a lot: start over rather than grow
		e.rejPrev = map[rejKey]uint64{}
	}
}

func (e *engine) stepShared(now time.Time, users map[int]*userAgg) {
	for uid, u := range users {
		over := u.limit > 0 && len(u.ips) > u.limit
		if !over && u.rejectWindow < sharedRejects {
			delete(e.shared, uid)
			continue
		}
		s := e.shared[uid]
		if s == nil {
			s = &sharedState{since: now.Unix()}
			e.shared[uid] = s
		}
		if over {
			s.over++
		} else {
			s.over = 0
		}
	}
	for uid := range e.shared {
		if users[uid] == nil {
			delete(e.shared, uid)
		}
	}
}

func (e *engine) stepSurge(now time.Time, users map[int]*userAgg) {
	dt := SampleInterval.Seconds()
	as, al := dt/surgeShortSecs, dt/surgeLongSecs
	seen := map[int]bool{}
	update := func(uid int, r float64) {
		s := e.surge[uid]
		if s == nil {
			if r <= 0 {
				return
			}
			s = &surgeState{short: r, long: r}
			e.surge[uid] = s
		}
		seen[uid] = true
		s.short += as * (r - s.short)
		s.long += al * (r - s.long)
		s.n++
		if r > 0 {
			s.lastActive = now
		}
		switch {
		case !s.on && s.n >= surgeWarmup && s.short >= surgeMinBps && s.short >= surgeFactor*s.long:
			s.on, s.since = true, now.Unix()
		case s.on && (s.short < surgeMinBps/2 || s.short < surgeClear*s.long):
			s.on = false
		}
	}
	for uid, u := range users {
		update(uid, float64(u.up+u.down))
	}
	for uid, s := range e.surge {
		if seen[uid] {
			continue
		}
		update(uid, 0)
		if now.Sub(s.lastActive) > idleForget {
			delete(e.surge, uid)
		}
	}
}

func (e *engine) stepDial(now time.Time, views []NodeView) {
	cut := now.Add(-alertWindow)
	live := map[int]bool{}
	for _, v := range views {
		if !v.DialSupported {
			continue
		}
		live[v.ID] = true
		d := e.dial[v.ID]
		if d == nil {
			// First sight: only a baseline, unless the counters are fresh.
			d = &dialState{epoch: v.Tracker.Created, total: v.DialTotal, fails: v.DialFails}
			e.dial[v.ID] = d
			continue
		}
		dt, df := int64(v.DialTotal)-int64(d.total), int64(v.DialFails)-int64(d.fails)
		if dt < 0 || df < 0 { // kernel restarted: counters reset
			dt, df = int64(v.DialTotal), int64(v.DialFails)
		}
		d.total, d.fails = v.DialTotal, v.DialFails
		if dt > 0 || df > 0 {
			d.events = append(d.events, dialEvent{now, dt, df})
		}
		i := 0
		for i < len(d.events) && d.events[i].t.Before(cut) {
			i++
		}
		d.events = d.events[i:]
	}
	for id := range e.dial {
		if !live[id] {
			delete(e.dial, id)
		}
	}
}

func (d *dialState) window() (total, fails int64) {
	for _, ev := range d.events {
		total += ev.total
		fails += ev.fails
	}
	return
}

func (e *engine) buildAlerts() {
	var out []Alert
	for uid, s := range e.shared {
		u := e.users[uid]
		if u == nil || (s.over < sharedSamples && u.rejectWindow < sharedRejects) {
			continue
		}
		out = append(out, Alert{Kind: "shared", User: uid, Value: int64(len(u.ips)), Limit: int64(u.limit), Rejects: u.rejectWindow, Since: s.since})
	}
	for uid, s := range e.surge {
		if s.on {
			out = append(out, Alert{Kind: "surge", User: uid, Value: int64(s.short), Limit: int64(s.long), Since: s.since})
		}
	}
	for id, d := range e.dial {
		t, f := d.window()
		if f >= dialMinFails && float64(f) >= dialMinRatio*float64(t) {
			since := e.sampled.Unix()
			if len(d.events) > 0 {
				since = d.events[0].t.Unix()
			}
			out = append(out, Alert{Kind: "dial", Node: id, Value: f, Limit: t, Since: since})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		return out[i].User < out[j].User
	})
	e.alerts = out
}

// ─── Output ──────────────────────────────────────────────────────────────

// Report is the /stats document.
type Report struct {
	Version  string       `json:"version"`
	Now      int64        `json:"now"`
	Sampled  int64        `json:"sampled"` // 0 = no sample yet
	Started  int64        `json:"started"` // process start
	Interval int          `json:"interval"`
	Machines []MachineOut `json:"machines"`
	Nodes    []NodeOut    `json:"nodes"`
	Total    TotalOut     `json:"total"`
	Users    []UserOut    `json:"users"`
	// UsersActive is the number of users with traffic or online IPs; Users is
	// capped at 500 (sorted by current rate).
	UsersActive int        `json:"users_active"`
	History     [][6]int64 `json:"history"` // [t, up B/s, down B/s, conns, online users, online IPs]
	Access      AccessOut  `json:"access"`
	Alerts      []Alert    `json:"alerts"`
}

type MachineOut struct {
	ID        int          `json:"id"`
	Panel     string       `json:"panel"`
	WS        int          `json:"ws"`
	Discovery ConnSnapshot `json:"discovery"`
	Status    ConnSnapshot `json:"status"`
}

type NodeOut struct {
	ID          int          `json:"id"`
	Name        string       `json:"name,omitempty"`
	Type        string       `json:"type,omitempty"`
	Protocol    string       `json:"protocol,omitempty"`
	Port        int          `json:"port,omitempty"`
	Kernel      string       `json:"kernel,omitempty"`
	State       string       `json:"state"` // running / starting / retrying
	Started     int64        `json:"started,omitempty"`
	Users       int          `json:"users"`
	OnlineUsers int          `json:"online_users"`
	OnlineIPs   int          `json:"online_ips"`
	Conns       int          `json:"conns"`
	UpBps       int64        `json:"up_bps"`
	DownBps     int64        `json:"down_bps"`
	AccessLog   bool         `json:"access_log"`
	Dial        *DialOut     `json:"dial,omitempty"`
	WS          int          `json:"ws"`
	Pull        ConnSnapshot `json:"pull"`
	Push        ConnSnapshot `json:"push"`
	Retry       *RetryOut    `json:"retry,omitempty"`
}

type DialOut struct {
	Total  int64 `json:"total"`  // attempts in the last 10 min
	Fails  int64 `json:"fails"`  // dial failures in the last 10 min
	Window int   `json:"window"` // seconds
}

type RetryOut struct {
	Attempts int    `json:"attempts"`
	Next     int64  `json:"next"`
	Error    string `json:"error,omitempty"`
	At       int64  `json:"at,omitempty"`
}

type TotalOut struct {
	OnlineUsers int   `json:"online_users"`
	OnlineIPs   int   `json:"online_ips"`
	Conns       int   `json:"conns"`
	UpBps       int64 `json:"up_bps"`
	DownBps     int64 `json:"down_bps"`
}

type UserOut struct {
	ID          int      `json:"id"`
	UUID        string   `json:"uuid,omitempty"` // first 8 characters
	UpBps       int64    `json:"up_bps"`
	DownBps     int64    `json:"down_bps"`
	Up          int64    `json:"up"`   // bytes since the node services started
	Down        int64    `json:"down"` // bytes since the node services started
	IPCount     int      `json:"ip_count"`
	IPs         []string `json:"ips"`
	Conns       int      `json:"conns"`
	DeviceLimit int      `json:"device_limit"`
	Nodes       []int    `json:"nodes"`
	Rejects     int64    `json:"rejects,omitempty"` // device-limit refusals, last 10 min
}

func shortUUID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func sortedIPs(m map[string]bool, max int) []string {
	out := make([]string, 0, len(m))
	for ip := range m {
		out = append(out, ip)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func (e *engine) report(now time.Time) Report {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := Report{Version: version, Now: now.Unix(), Started: startedAt.Unix(), Interval: int(SampleInterval / time.Second),
		Machines: []MachineOut{}, Nodes: []NodeOut{}, Users: []UserOut{}, History: e.history, Alerts: e.alerts}
	if r.History == nil {
		r.History = [][6]int64{}
	}
	if r.Alerts == nil {
		r.Alerts = []Alert{}
	}
	if !e.sampled.IsZero() {
		r.Sampled = e.sampled.Unix()
	}

	byID := map[int]*NodeOut{}
	var order []int
	accessOn := false
	for _, v := range e.views {
		iv := interval(v)
		n := &NodeOut{ID: v.ID, Protocol: v.Protocol, Port: v.Port, Kernel: v.Kernel, State: "starting",
			Users: len(v.Users), AccessLog: v.AccessLog, WS: v.WS, Pull: v.Pull, Push: v.Push}
		if !v.Tracker.Created.IsZero() {
			n.Started = v.Tracker.Created.Unix()
		}
		if v.Running {
			n.State = "running"
			n.UpBps, n.DownBps, n.Conns = v.Tracker.OutCycle/iv, v.Tracker.InCycle/iv, v.Tracker.ConnCount
			for _, ips := range v.Tracker.AliveIPs {
				if len(ips) > 0 {
					n.OnlineUsers++
					n.OnlineIPs += len(ips)
				}
			}
		}
		if v.AccessLog {
			accessOn = true
		}
		if d := e.dial[v.ID]; d != nil {
			t, f := d.window()
			n.Dial = &DialOut{Total: t, Fails: f, Window: int(alertWindow / time.Second)}
		}
		byID[v.ID] = n
		order = append(order, v.ID)
	}
	for _, m := range e.machines {
		r.Machines = append(r.Machines, MachineOut{ID: m.ID, Panel: m.Panel, WS: m.WS, Discovery: m.Discovery, Status: m.Status})
		for _, mn := range m.Nodes {
			n := byID[mn.ID]
			if n == nil {
				n = &NodeOut{ID: mn.ID, State: "starting", WS: -1}
				byID[mn.ID] = n
				order = append(order, mn.ID)
			}
			n.Name, n.Type = mn.Name, mn.Type
			if n.Protocol == "" {
				n.Protocol = mn.Type
			}
			if mn.Attempts > 0 {
				n.Retry = &RetryOut{Attempts: mn.Attempts, Next: mn.NextRetry, Error: mn.LastError, At: mn.LastExit}
				if !mn.Running {
					n.State = "retrying"
				}
			}
		}
	}
	sort.Ints(order)
	for _, id := range order {
		n := byID[id]
		r.Nodes = append(r.Nodes, *n)
		r.Total.UpBps += n.UpBps
		r.Total.DownBps += n.DownBps
		r.Total.Conns += n.Conns
	}

	type kv struct {
		id int
		u  *userAgg
	}
	list := make([]kv, 0, len(e.users))
	for id, u := range e.users {
		if len(u.ips) > 0 {
			r.Total.OnlineUsers++
			r.Total.OnlineIPs += len(u.ips)
		}
		if len(u.ips) > 0 || u.up+u.down > 0 || u.conns > 0 {
			list = append(list, kv{id, u})
		}
	}
	r.UsersActive = len(list)
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i].u, list[j].u
		if a.up+a.down != b.up+b.down {
			return a.up+a.down > b.up+b.down
		}
		if len(a.ips) != len(b.ips) {
			return len(a.ips) > len(b.ips)
		}
		return list[i].id < list[j].id
	})
	if len(list) > maxUsersOut {
		list = list[:maxUsersOut]
	}
	for _, x := range list {
		u := x.u
		nodes := u.nodes
		if nodes == nil {
			nodes = []int{}
		}
		r.Users = append(r.Users, UserOut{ID: x.id, UUID: shortUUID(u.uuid), UpBps: u.up, DownBps: u.down, Up: u.totUp, Down: u.totDown,
			IPCount: len(u.ips), IPs: sortedIPs(u.ips, maxIPsOut), Conns: u.conns, DeviceLimit: u.limit, Nodes: nodes, Rejects: u.rejectWindow})
	}
	r.Access = e.access.report(now, accessOn, 30)
	return r
}

// UserReport is the /stats/user document.
type UserReport struct {
	ID          int        `json:"id"`
	UUID        string     `json:"uuid,omitempty"`
	Online      bool       `json:"online"`
	IPs         []string   `json:"ips"`
	RejectedIPs []string   `json:"rejected_ips"` // recently refused by the device limit
	DeviceLimit int        `json:"device_limit"`
	AccessLog   bool       `json:"access_log"`
	Since       int64      `json:"since"` // start of the access aggregation window
	Hosts       []HostStat `json:"hosts"` // top destinations by traffic
}

func (e *engine) userReport(uid int) UserReport {
	e.mu.Lock()
	r := UserReport{ID: uid, IPs: []string{}, RejectedIPs: []string{}, Hosts: []HostStat{}}
	if u := e.users[uid]; u != nil {
		r.UUID, r.Online, r.DeviceLimit = shortUUID(u.uuid), len(u.ips) > 0, u.limit
		r.IPs = sortedIPs(u.ips, 256)
		seen := map[string]bool{}
		for i := len(u.rejIPs) - 1; i >= 0; i-- {
			if ip := u.rejIPs[i]; !seen[ip] {
				seen[ip] = true
				r.RejectedIPs = append(r.RejectedIPs, ip)
			}
		}
	}
	for _, v := range e.views {
		if v.AccessLog {
			r.AccessLog = true
		}
		if r.UUID == "" {
			if m, ok := v.Users[uid]; ok {
				r.UUID, r.DeviceLimit = shortUUID(m.UUID), m.DeviceLimit
			}
		}
	}
	e.mu.Unlock()
	r.Since, r.Hosts = e.access.user(uid, 50)
	if r.Hosts == nil {
		r.Hosts = []HostStat{}
	}
	return r
}

// writeCounters writes the line-based sample for shell consumers (the
// router plugin's history sampler):
//
//	t <now> <process start>
//	n <node> <epoch> <running 0|1> <up B/s> <down B/s> <conns> <online users> <online IPs>
//	u <node> <epoch> <user> <up bytes> <down bytes>        cumulative since <epoch>
//	a <kind> <user|node> <value> <limit> <since>
//
// <epoch> identifies one run of a node's counters (unix seconds of its
// start): when it changes, the counters started again from zero.
func (e *engine) writeCounters(w io.Writer, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "t %d %d\n", now.Unix(), startedAt.Unix())
	for _, v := range e.views {
		iv, ep := interval(v), v.Tracker.Created.Unix()
		run, up, down, conns, ou, oi := 0, int64(0), int64(0), 0, 0, 0
		if v.Running {
			run, up, down, conns = 1, v.Tracker.OutCycle/iv, v.Tracker.InCycle/iv, v.Tracker.ConnCount
			for _, ips := range v.Tracker.AliveIPs {
				if len(ips) > 0 {
					ou++
					oi += len(ips)
				}
			}
		}
		fmt.Fprintf(&b, "n %d %d %d %d %d %d %d %d\n", v.ID, ep, run, up, down, conns, ou, oi)
		for uid, t := range v.Tracker.Totals {
			fmt.Fprintf(&b, "u %d %d %d %d %d\n", v.ID, ep, uid, t[0], t[1])
		}
	}
	for _, a := range e.alerts {
		subj := a.User
		if a.Kind == "dial" {
			subj = a.Node
		}
		fmt.Fprintf(&b, "a %s %d %d %d %d\n", a.Kind, subj, a.Value, a.Limit, a.Since)
	}
	io.WriteString(w, b.String())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}
