package localstats

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

func TestCheckLoopback(t *testing.T) {
	ok := map[string]string{
		"":                "",
		"127.0.0.1:65532": "127.0.0.1:65532",
		"[::1]:9000":      "[::1]:9000",
		"localhost:1234":  "127.0.0.1:1234",
		" 127.0.0.5:80 ":  "127.0.0.5:80",
	}
	for in, want := range ok {
		got, err := checkLoopback(in)
		if err != nil || got != want {
			t.Errorf("checkLoopback(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"0.0.0.0:65532", ":65532", "192.168.1.1:80", "example.com:80", "127.0.0.1", "127.0.0.1:0"} {
		if _, err := checkLoopback(bad); err == nil {
			t.Errorf("checkLoopback(%q) should fail", bad)
		}
	}
}

func TestDisabledByDefault(t *testing.T) {
	// The test binary runs without LB_NODE_STATS_LISTEN.
	if Enabled() {
		t.Skip("LB_NODE_STATS_LISTEN set in the environment")
	}
	unreg := RegisterNode(fakeSource{})
	unreg()
	ns, _ := sources()
	if len(ns) != 0 {
		t.Fatal("RegisterNode must be a no-op when disabled")
	}
	AddAccess([]model.AccessRecord{{UserID: 1, DestHost: "a.com"}}) // no-op, must not panic
}

type fakeSource struct{}

func (fakeSource) StatsView() NodeView { return NodeView{} }

func TestConnStat(t *testing.T) {
	var nilStat *ConnStat
	nilStat.OK()
	nilStat.Fail(errors.New("x"))
	if (nilStat.Snapshot() != ConnSnapshot{}) {
		t.Fatal("nil snapshot")
	}
	var c ConnStat
	c.Fail(errors.New("timeout"))
	c.Fail(errors.New(strings.Repeat("e", 500)))
	s := c.Snapshot()
	if s.Fails != 2 || s.FailsTotal != 2 || s.LastFail == 0 || s.LastOK != 0 || len(s.LastError) > 310 {
		t.Fatalf("after fails: %+v", s)
	}
	if s.FailSince == 0 || s.FailSince > s.LastFail {
		t.Fatalf("streak start: %+v", s)
	}
	c.OK()
	s = c.Snapshot()
	if s.Fails != 0 || s.FailsTotal != 2 || s.LastOK == 0 || s.FailSince != 0 {
		t.Fatalf("after ok: %+v", s)
	}
}

// view builds a running node view whose tracker saw the given cycle.
func view(id int, created time.Time, speed map[int][2]int64, ips map[int]map[string]bool, totals map[int][2]int64, users map[int]UserMeta) NodeView {
	var in, out int64
	for _, d := range speed {
		out += d[0]
		in += d[1]
	}
	return NodeView{ID: id, Protocol: "vless", Port: 443, Kernel: "singbox", Running: true, TrackInterval: 10,
		Users: users, WS: 1,
		Tracker: tracker.View{Created: created, UserSpeed: speed, AliveIPs: ips, Totals: totals, ConnCount: 3, InCycle: in, OutCycle: out}}
}

func TestStepAggregatesAcrossNodes(t *testing.T) {
	e := newEngine()
	t0 := time.Unix(1_700_000_000, 0)
	users := map[int]UserMeta{7: {UUID: "abcdef0123456789", DeviceLimit: 3}, 8: {UUID: "u8"}}
	a := view(1, t0, map[int][2]int64{7: {1000, 9000}}, map[int]map[string]bool{7: {"1.1.1.1": true}, 8: {"2.2.2.2": true}},
		map[int][2]int64{7: {5000, 50000}, 8: {10, 20}}, users)
	a.UserConns = map[int]int{7: 4}
	b := view(2, t0, map[int][2]int64{7: {500, 500}}, map[int]map[string]bool{7: {"1.1.1.1": true, "3.3.3.3": true}},
		map[int][2]int64{7: {100, 100}}, users)
	e.step(t0.Add(time.Minute), []NodeView{b, a}, []MachineView{{ID: 9, Panel: "panel.example", WS: 1,
		Nodes: []MachineNode{{ID: 1, Name: "hk", Type: "vless", Running: true}, {ID: 2, Type: "vless", Running: true},
			{ID: 3, Name: "broken", Type: "trojan", Attempts: 2, NextRetry: 123, LastError: "listen tcp :443: address already in use"}}}})
	r := e.report(t0.Add(time.Minute))

	if len(r.Nodes) != 3 || r.Nodes[0].ID != 1 || r.Nodes[0].Name != "hk" || r.Nodes[2].State != "retrying" || r.Nodes[2].Retry == nil ||
		!strings.Contains(r.Nodes[2].Retry.Error, "address already in use") {
		t.Fatalf("nodes: %+v", r.Nodes)
	}
	if r.Nodes[0].UpBps != 100 || r.Nodes[0].DownBps != 900 || r.Nodes[0].OnlineUsers != 2 || r.Nodes[0].OnlineIPs != 2 {
		t.Fatalf("node 1: %+v", r.Nodes[0])
	}
	if r.Total.OnlineUsers != 2 || r.Total.OnlineIPs != 3 || r.Total.UpBps != 150 || r.Total.DownBps != 950 || r.Total.Conns != 6 {
		t.Fatalf("total: %+v", r.Total)
	}
	if len(r.Users) != 2 || r.Users[0].ID != 7 {
		t.Fatalf("users: %+v", r.Users)
	}
	u := r.Users[0]
	if u.UUID != "abcdef01" || u.UpBps != 150 || u.DownBps != 950 || u.IPCount != 2 || u.DeviceLimit != 3 ||
		u.Conns != 4 || u.Up != 5100 || u.Down != 50100 || len(u.Nodes) != 2 {
		t.Fatalf("user 7: %+v", u)
	}
	if len(r.History) != 1 || r.History[0][1] != 150 || r.History[0][4] != 2 || r.History[0][5] != 3 {
		t.Fatalf("history: %v", r.History)
	}
	if len(r.Machines) != 1 || r.Machines[0].Panel != "panel.example" {
		t.Fatalf("machines: %+v", r.Machines)
	}
	if len(r.Alerts) != 0 {
		t.Fatalf("unexpected alerts: %+v", r.Alerts)
	}
}

func TestStoppedNodeHasNoSpeed(t *testing.T) {
	e := newEngine()
	v := view(1, time.Now(), map[int][2]int64{1: {100, 100}}, map[int]map[string]bool{1: {"1.1.1.1": true}}, nil, nil)
	v.Running = false
	e.step(time.Now(), []NodeView{v}, nil)
	r := e.report(time.Now())
	if r.Nodes[0].State != "starting" || r.Nodes[0].UpBps != 0 || r.Total.OnlineUsers != 0 || len(r.Users) != 0 {
		t.Fatalf("stopped node leaked stale data: %+v %+v", r.Nodes[0], r.Total)
	}
}

func TestHistoryBounded(t *testing.T) {
	e := newEngine()
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < historyLen+25; i++ {
		e.step(t0.Add(time.Duration(i)*SampleInterval), nil, nil)
	}
	r := e.report(t0)
	if len(r.History) != historyLen || r.History[historyLen-1][0] != t0.Add(time.Duration(historyLen+24)*SampleInterval).Unix() {
		t.Fatalf("history len %d last %v", len(r.History), r.History[len(r.History)-1])
	}
}

func TestSharedAlertOverLimit(t *testing.T) {
	e := newEngine()
	t0 := time.Unix(1_700_000_000, 0)
	users := map[int]UserMeta{5: {UUID: "u5", DeviceLimit: 2}}
	over := map[int]map[string]bool{5: {"1.1.1.1": true, "2.2.2.2": true, "3.3.3.3": true}}
	for i := 0; i < sharedSamples-1; i++ {
		e.step(t0.Add(time.Duration(i)*SampleInterval), []NodeView{view(1, t0, nil, over, nil, users)}, nil)
	}
	if len(e.report(t0).Alerts) != 0 {
		t.Fatal("alert before the condition held long enough")
	}
	e.step(t0.Add(time.Minute), []NodeView{view(1, t0, nil, over, nil, users)}, nil)
	al := e.report(t0).Alerts
	if len(al) != 1 || al[0].Kind != "shared" || al[0].User != 5 || al[0].Value != 3 || al[0].Limit != 2 || al[0].Since != t0.Unix() {
		t.Fatalf("alerts: %+v", al)
	}
	// Back under the limit: cleared.
	e.step(t0.Add(2*time.Minute), []NodeView{view(1, t0, nil, map[int]map[string]bool{5: {"1.1.1.1": true}}, nil, users)}, nil)
	if al := e.report(t0).Alerts; len(al) != 0 {
		t.Fatalf("alert not cleared: %+v", al)
	}
	// No device limit: never flagged.
	e2 := newEngine()
	for i := 0; i < 5; i++ {
		e2.step(t0.Add(time.Duration(i)*SampleInterval), []NodeView{view(1, t0, nil, over, nil, map[int]UserMeta{5: {}})}, nil)
	}
	if al := e2.report(t0).Alerts; len(al) != 0 {
		t.Fatalf("unlimited user flagged: %+v", al)
	}
}

func TestSharedAlertFromDeviceRejects(t *testing.T) {
	e := newEngine()
	t0 := time.Unix(1_700_000_000, 0)
	users := map[int]UserMeta{5: {UUID: "u5", DeviceLimit: 1}}
	ips := map[int]map[string]bool{5: {"1.1.1.1": true}}
	mk := func(n uint64) NodeView {
		v := view(1, t0, nil, ips, nil, users)
		v.Rejects = map[int]RejectStat{5: {Count: n, IPs: []string{"9.9.9.9"}}}
		return v
	}
	e.step(t0, []NodeView{mk(2)}, nil) // first sight counts as new refusals
	if len(e.report(t0).Alerts) != 0 {
		t.Fatal("2 refusals should not alert")
	}
	e.step(t0.Add(SampleInterval), []NodeView{mk(6)}, nil)
	al := e.report(t0).Alerts
	if len(al) != 1 || al[0].Kind != "shared" || al[0].Rejects != 6 {
		t.Fatalf("alerts: %+v", al)
	}
	ur := e.userReport(5)
	if len(ur.RejectedIPs) != 1 || ur.RejectedIPs[0] != "9.9.9.9" || !ur.Online {
		t.Fatalf("user report: %+v", ur)
	}
	// Refusals age out of the 10-minute window.
	e.step(t0.Add(alertWindow+time.Minute), []NodeView{mk(6)}, nil)
	if al := e.report(t0).Alerts; len(al) != 0 {
		t.Fatalf("old refusals still alerting: %+v", al)
	}
}

func TestSurgeAlert(t *testing.T) {
	e := newEngine()
	t0 := time.Unix(1_700_000_000, 0)
	ips := map[int]map[string]bool{3: {"1.1.1.1": true}}
	at := func(i int, bps int64) {
		sp := map[int][2]int64{3: {0, bps * 10}}
		e.step(t0.Add(time.Duration(i)*SampleInterval), []NodeView{view(1, t0, sp, ips, nil, nil)}, nil)
	}
	i := 0
	for ; i < 60; i++ { // 10 min of a steady 200 KB/s baseline
		at(i, 200<<10)
	}
	if len(e.report(t0).Alerts) != 0 {
		t.Fatal("steady traffic flagged")
	}
	for ; i < 120; i++ { // jumps to 20 MB/s
		at(i, 20<<20)
	}
	al := e.report(t0).Alerts
	if len(al) != 1 || al[0].Kind != "surge" || al[0].User != 3 || al[0].Value < surgeMinBps || al[0].Limit <= 0 {
		t.Fatalf("alerts: %+v", al)
	}
	for ; i < 200; i++ { // traffic stops: clears
		at(i, 0)
	}
	if al := e.report(t0).Alerts; len(al) != 0 {
		t.Fatalf("surge not cleared: %+v", al)
	}
	// A user that only just appeared is not flagged during warm-up.
	e2 := newEngine()
	for j := 0; j < surgeWarmup-1; j++ {
		sp := map[int][2]int64{4: {0, (50 << 20) * 10}}
		e2.step(t0.Add(time.Duration(j)*SampleInterval), []NodeView{view(1, t0, sp, nil, nil, nil)}, nil)
	}
	if al := e2.report(t0).Alerts; len(al) != 0 {
		t.Fatalf("flagged during warm-up: %+v", al)
	}
}

func TestSurgeStateForgotten(t *testing.T) {
	e := newEngine()
	t0 := time.Unix(1_700_000_000, 0)
	e.step(t0, []NodeView{view(1, t0, map[int][2]int64{9: {100, 100}}, nil, nil, nil)}, nil)
	if e.surge[9] == nil {
		t.Fatal("state not created")
	}
	e.step(t0.Add(idleForget+time.Minute), []NodeView{view(1, t0, nil, nil, nil, nil)}, nil)
	if e.surge[9] != nil {
		t.Fatal("idle user state kept")
	}
}

func TestDialAlert(t *testing.T) {
	e := newEngine()
	t0 := time.Unix(1_700_000_000, 0)
	mk := func(total, fails uint64) NodeView {
		v := view(1, t0, nil, nil, nil, nil)
		v.DialSupported, v.DialTotal, v.DialFails = true, total, fails
		return v
	}
	e.step(t0, []NodeView{mk(1000, 500)}, nil) // baseline only: history before we looked
	if len(e.report(t0).Alerts) != 0 {
		t.Fatal("baseline must not alert")
	}
	e.step(t0.Add(SampleInterval), []NodeView{mk(1100, 510)}, nil) // 10 of 100: below threshold
	if len(e.report(t0).Alerts) != 0 {
		t.Fatal("few failures alerted")
	}
	e.step(t0.Add(2*SampleInterval), []NodeView{mk(1200, 550)}, nil) // 50 of 200 in window
	al := e.report(t0).Alerts
	if len(al) != 1 || al[0].Kind != "dial" || al[0].Node != 1 || al[0].Value != 50 || al[0].Limit != 200 {
		t.Fatalf("alerts: %+v", al)
	}
	if d := e.report(t0).Nodes[0].Dial; d == nil || d.Fails != 50 || d.Total != 200 {
		t.Fatalf("node dial: %+v", d)
	}
	// Kernel restart: counters reset to small numbers, counted as fresh.
	e.step(t0.Add(3*SampleInterval), []NodeView{mk(10, 1)}, nil)
	if d := e.report(t0).Nodes[0].Dial; d.Total != 210 || d.Fails != 51 {
		t.Fatalf("after reset: %+v", d)
	}
	// Window expires.
	e.step(t0.Add(alertWindow+time.Hour), []NodeView{mk(10, 1)}, nil)
	if al := e.report(t0).Alerts; len(al) != 0 {
		t.Fatalf("expired window still alerting: %+v", al)
	}
}

func TestCountersFormat(t *testing.T) {
	e := newEngine()
	t0 := time.Unix(1_700_000_000, 0)
	v := view(4, t0, map[int][2]int64{7: {100, 200}}, map[int]map[string]bool{7: {"1.1.1.1": true}}, map[int][2]int64{7: {1000, 2000}}, nil)
	v.Pull = ConnSnapshot{Fails: 3, FailSince: 1690, LastFail: 1700, LastOK: 1600, LastError: `Get "x": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`}
	v.Push = ConnSnapshot{Fails: 1, FailSince: 1650, LastFail: 1650, LastError: "502 Bad Gateway"}
	e.step(t0, []NodeView{v}, []MachineView{{ID: 9, Discovery: ConnSnapshot{LastOK: 1500}}})
	var b strings.Builder
	e.writeCounters(&b, t0)
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	want := []string{
		fmt.Sprintf("t %d %d", t0.Unix(), startedAt.Unix()),
		fmt.Sprintf("n 4 %d 1 10 20 3 1 1", t0.Unix()),
		fmt.Sprintf("u 4 %d 7 1000 2000", t0.Unix()),
		"c discovery 9 0 0 0 1500 0",
		"c status 9 0 0 0 0 0",
		"c pull 4 3 1690 1700 1600 1",
		"c push 4 1 1650 1650 0 0",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("counters:\n%s\nwant:\n%s", b.String(), strings.Join(want, "\n"))
	}
}

func TestIsTimeout(t *testing.T) {
	for msg, want := range map[string]bool{
		`Post "https://p/api": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`: true,
		"context deadline exceeded":    true,
		"dial tcp: connection refused": false,
		"":                             false,
	} {
		if got := (ConnSnapshot{LastError: msg}).IsTimeout(); got != want {
			t.Errorf("IsTimeout(%q) = %v", msg, got)
		}
	}
}

func TestHandler(t *testing.T) {
	old := eng
	defer func() { eng = old }()
	eng = newEngine()
	t0 := time.Now()
	eng.step(t0, []NodeView{view(1, t0, map[int][2]int64{7: {10, 10}}, map[int]map[string]bool{7: {"1.1.1.1": true}}, nil, map[int]UserMeta{7: {UUID: "x"}})}, nil)
	eng.access.add(t0, []model.AccessRecord{{UserID: 7, DestHost: "Example.COM", Upload: 10, Download: 90}})
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	var r Report
	getJSON(t, srv.URL+"/stats", &r)
	if r.Sampled == 0 || len(r.Nodes) != 1 || len(r.Users) != 1 || r.Access.Records != 1 || r.Access.ByBytes[0].Host != "example.com" {
		t.Fatalf("report: %+v", r)
	}
	var ur UserReport
	getJSON(t, srv.URL+"/stats/user?id=7", &ur)
	if ur.ID != 7 || len(ur.Hosts) != 1 || ur.Hosts[0].Bytes != 100 {
		t.Fatalf("user report: %+v", ur)
	}
	res, err := http.Get(srv.URL + "/stats/user?id=abc")
	if err != nil || res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad id: %v %v", res, err)
	}
	res.Body.Close()
	res, err = http.Get(srv.URL + "/stats/counters")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("counters: %v %v", res, err)
	}
	res.Body.Close()
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

// Empty engine must still produce arrays (the page expects [] not null).
func TestEmptyReportJSON(t *testing.T) {
	b, _ := json.Marshal(newEngine().report(time.Now()))
	for _, k := range []string{`"nodes":[]`, `"users":[]`, `"history":[]`, `"alerts":[]`, `"by_bytes":[]`, `"machines":[]`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing %s in %s", k, b)
		}
	}
}

func TestConcurrentSampleAndRead(t *testing.T) {
	e := newEngine()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	t0 := time.Now()
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			e.step(t0.Add(time.Duration(i)*time.Second), []NodeView{view(1, t0, map[int][2]int64{i % 50: {1, 1}}, nil, nil, nil)}, nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			e.access.add(time.Now(), []model.AccessRecord{{UserID: i % 7, DestHost: fmt.Sprintf("h%d.com", i%100), Upload: 1}})
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = e.report(time.Now())
			_ = e.userReport(3)
			var b strings.Builder
			e.writeCounters(&b, time.Now())
		}
	}()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}
