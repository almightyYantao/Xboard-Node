// Package localstats serves a read-only statistics endpoint on the loopback
// interface for the device the node runs on (e.g. a router plugin page).
//
// It is off unless LB_NODE_STATS_LISTEN is set to a loopback address such as
// "127.0.0.1:65532". When off, Register* are no-ops and nothing is sampled,
// so upstream behaviour is unchanged.
//
// Data flow: node services and the machine orchestrator register themselves
// as sources. A sampler goroutine reads them every SampleInterval (tracker
// snapshots are lock-free), derives history / alerts, and caches the result.
// HTTP handlers only read that cache, so a request never reaches into the
// services or the kernel.
package localstats

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

// EnvListen enables the endpoint: a loopback host:port to listen on.
const EnvListen = "LB_NODE_STATS_LISTEN"

// SampleInterval is how often sources are sampled (matches the tracker tick).
const SampleInterval = 10 * time.Second

var (
	addrOnce sync.Once
	addrVal  string
	addrErr  error
)

// ListenAddr returns the configured listen address ("" when disabled) or an
// error when it is set but not a loopback address.
func ListenAddr() (string, error) {
	addrOnce.Do(func() { addrVal, addrErr = checkLoopback(os.Getenv(EnvListen)) })
	return addrVal, addrErr
}

func checkLoopback(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", fmt.Errorf("%s=%q: %w", EnvListen, v, err)
	}
	if port == "" || port == "0" {
		return "", fmt.Errorf("%s=%q: port required", EnvListen, v)
	}
	if host == "localhost" {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("%s=%q: only loopback addresses are allowed", EnvListen, v)
	}
	return v, nil
}

// Enabled reports whether the local stats endpoint is configured.
func Enabled() bool {
	a, err := ListenAddr()
	return a != "" && err == nil
}

// ─── Panel connectivity counters ─────────────────────────────────────────

// ConnStat records the outcome of calls to the panel. All methods are safe
// for concurrent use and on a nil receiver. Cost: a few atomic stores.
type ConnStat struct {
	lastOK, lastFail atomic.Int64
	since            atomic.Int64 // first failure of the current streak
	fails, total     atomic.Int64
	lastErr          atomic.Pointer[string]
}

// OK records a successful call.
func (c *ConnStat) OK() {
	if c == nil {
		return
	}
	c.lastOK.Store(time.Now().Unix())
	c.fails.Store(0)
}

// Fail records a failed call.
func (c *ConnStat) Fail(err error) {
	if c == nil {
		return
	}
	now := time.Now().Unix()
	c.lastFail.Store(now)
	if c.fails.Add(1) == 1 {
		c.since.Store(now)
	}
	c.total.Add(1)
	msg := "unknown error"
	if err != nil {
		msg = err.Error()
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	c.lastErr.Store(&msg)
}

// IsTimeout reports whether the latest failure was a request timeout (the
// stuck-connection symptom the router plugin's watchdog acts on).
func (s ConnSnapshot) IsTimeout() bool {
	return strings.Contains(s.LastError, "Client.Timeout") || strings.Contains(s.LastError, "deadline exceeded")
}

// ConnSnapshot is a copy of a ConnStat.
type ConnSnapshot struct {
	LastOK     int64  `json:"last_ok"`              // unix seconds, 0 = never
	LastFail   int64  `json:"last_fail"`            // unix seconds, 0 = never
	LastError  string `json:"last_error,omitempty"` // message of the latest failure
	Fails      int64  `json:"fails"`                // consecutive failures since the last success
	FailSince  int64  `json:"fail_since,omitempty"` // when the current streak began (Fails > 0)
	FailsTotal int64  `json:"fails_total"`          // failures since start
}

// Snapshot returns a copy.
func (c *ConnStat) Snapshot() ConnSnapshot {
	if c == nil {
		return ConnSnapshot{}
	}
	s := ConnSnapshot{LastOK: c.lastOK.Load(), LastFail: c.lastFail.Load(), Fails: c.fails.Load(), FailsTotal: c.total.Load()}
	if s.Fails > 0 {
		s.FailSince = c.since.Load()
	}
	if p := c.lastErr.Load(); p != nil {
		s.LastError = *p
	}
	return s
}

// ─── Sources ─────────────────────────────────────────────────────────────

// UserMeta is what the stats need to know about a panel user.
type UserMeta struct {
	UUID        string
	DeviceLimit int
}

// RejectStat is a user's device-limit refusals (cumulative per kernel run).
type RejectStat struct {
	Count uint64
	IPs   []string
}

// NodeView is one node service at a point in time. Maps are read-only.
type NodeView struct {
	ID            int
	Protocol      string
	Port          int
	Kernel        string
	Running       bool
	TrackInterval int // seconds per tracker cycle (speed = delta / interval)
	Users         map[int]UserMeta
	Tracker       tracker.View
	UserConns     map[int]int // nil when the kernel can't tell
	AccessLog     bool
	DialSupported bool
	DialTotal     uint64
	DialFails     uint64
	Rejects       map[int]RejectStat
	WS            int // -1 = no push channel, 0 = disconnected, 1 = connected
	Pull          ConnSnapshot
	Push          ConnSnapshot
}

// NodeSource is implemented by service.Service.
type NodeSource interface {
	StatsView() NodeView
}

// MachineNode is a node the panel assigned to this machine.
type MachineNode struct {
	ID        int
	Name      string
	Type      string
	Running   bool   // a service is currently attached
	Attempts  int    // failed starts in a row (0 = none)
	NextRetry int64  // unix seconds of the next restart attempt
	LastError string // why the last start failed
	LastExit  int64  // unix seconds of the last failure
}

// MachineView is the machine orchestrator at a point in time.
type MachineView struct {
	ID        int
	Panel     string // panel host (no path / token)
	WS        int    // -1 = REST only, 0 = disconnected, 1 = connected
	Discovery ConnSnapshot
	Status    ConnSnapshot
	Nodes     []MachineNode
}

// MachineSource is implemented by machine.Orchestrator.
type MachineSource interface {
	StatsMachineView() MachineView
}

var reg struct {
	mu       sync.Mutex
	nodes    map[NodeSource]struct{}
	machines map[MachineSource]struct{}
}

// RegisterNode adds a node source; call the returned func when it stops.
func RegisterNode(src NodeSource) func() {
	if !Enabled() || src == nil {
		return func() {}
	}
	reg.mu.Lock()
	if reg.nodes == nil {
		reg.nodes = make(map[NodeSource]struct{})
	}
	reg.nodes[src] = struct{}{}
	reg.mu.Unlock()
	return func() {
		reg.mu.Lock()
		delete(reg.nodes, src)
		reg.mu.Unlock()
	}
}

// RegisterMachine adds a machine source; call the returned func when it stops.
func RegisterMachine(src MachineSource) func() {
	if !Enabled() || src == nil {
		return func() {}
	}
	reg.mu.Lock()
	if reg.machines == nil {
		reg.machines = make(map[MachineSource]struct{})
	}
	reg.machines[src] = struct{}{}
	reg.mu.Unlock()
	return func() {
		reg.mu.Lock()
		delete(reg.machines, src)
		reg.mu.Unlock()
	}
}

func sources() ([]NodeSource, []MachineSource) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	ns := make([]NodeSource, 0, len(reg.nodes))
	for s := range reg.nodes {
		ns = append(ns, s)
	}
	ms := make([]MachineSource, 0, len(reg.machines))
	for s := range reg.machines {
		ms = append(ms, s)
	}
	return ns, ms
}

// ─── Server ──────────────────────────────────────────────────────────────

var (
	version   = "dev"
	startedAt = time.Now()
	eng       = newEngine()
)

// Start listens on the configured address and starts sampling. It returns
// nil without doing anything when the endpoint is disabled. A listen error
// is returned (the caller should log it and carry on — stats are optional).
func Start(ctx context.Context, ver string) error {
	addr, err := ListenAddr()
	if err != nil {
		return err
	}
	if addr == "" {
		return nil
	}
	if ver != "" {
		version = ver
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := &http.Server{Handler: Handler(), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			nlog.Core().Warn("local stats server stopped", "error", err)
		}
	}()
	go eng.run(ctx)
	nlog.Core().Info("local stats listening", "addr", addr)
	return nil
}

// Handler returns the HTTP handler (exported for tests).
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, eng.report(time.Now()))
	})
	mux.HandleFunc("/stats/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		eng.writeCounters(w, time.Now())
	})
	mux.HandleFunc("/stats/user", func(w http.ResponseWriter, r *http.Request) {
		var uid int
		if _, err := fmt.Sscanf(r.URL.Query().Get("id"), "%d", &uid); err != nil || uid <= 0 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		writeJSON(w, eng.userReport(uid))
	})
	return mux
}
