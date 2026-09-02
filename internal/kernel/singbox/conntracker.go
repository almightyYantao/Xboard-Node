package singbox

import (
	"context"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/acl"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// accessBufMax caps the in-memory access-log buffer; excess records are dropped
// to bound memory if the panel push falls behind.
const accessBufMax = 50000

// ipPool caches ipSnapshot maps to reduce allocations.
var ipPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]struct{}, 16)
	},
}

// ─── Per-user statistics ────────────────────────────────────────────────────

// userStats holds per-user traffic counters and alive IP tracking.
// Traffic counters are lock-free atomics (read on every packet).
// IP tracking uses a lightweight mutex (only touched at connect/disconnect).
type userStats struct {
	upload   atomic.Int64
	download atomic.Int64

	mu        sync.RWMutex   // RWMutex for concurrent reads
	ips       map[string]int // sourceIP → refcount (number of active conns from that IP)
	connCount int            // total active connections
}

// addConn registers a new connection from sourceIP.
func (u *userStats) addConn(sourceIP string) {
	u.mu.Lock()
	u.connCount++
	u.ips[sourceIP]++
	u.mu.Unlock()
}

// removeConn unregisters a connection from sourceIP.
func (u *userStats) removeConn(sourceIP string) {
	u.mu.Lock()
	u.connCount--
	u.ips[sourceIP]--
	if u.ips[sourceIP] <= 0 {
		delete(u.ips, sourceIP)
	}
	u.mu.Unlock()
}

// distinctIPs returns the number of distinct IPs currently connected.
func (u *userStats) distinctIPs() int {
	u.mu.Lock()
	n := len(u.ips)
	u.mu.Unlock()
	return n
}

// ipSnapshot returns a pooled copy of the current IP set.
func (u *userStats) ipSnapshot() map[string]struct{} {
	cp := ipPool.Get().(map[string]struct{})
	for k := range cp {
		delete(cp, k)
	}
	u.mu.Lock()
	for ip := range u.ips {
		cp[ip] = struct{}{}
	}
	u.mu.Unlock()
	return cp
}

// releaseIPSnapshot returns the snapshot to pool.
// Large maps are discarded to prevent memory bloat.
func releaseIPSnapshot(m map[string]struct{}) {
	// Discard large maps to prevent pool memory bloat
	if len(m) > 64 {
		return
	}
	ipPool.Put(m)
}

// aliveIPList returns the set of alive IPs as a boolean map (for reporting).
func (u *userStats) aliveIPList() map[string]bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.ips) == 0 {
		return nil
	}
	result := make(map[string]bool, len(u.ips))
	for ip := range u.ips {
		result[ip] = true
	}
	return result
}

// ─── ConnTracker ────────────────────────────────────────────────────────────

// ConnTracker provides per-user traffic counting, alive IP tracking, device
// limit gate-keeping, and per-user speed limiting for the sing-box kernel.
//
// Architecture: instead of maintaining a per-connection map (O(connections)),
// it maintains per-user atomic counters and IP refcount sets (O(users)).
// This means:
//   - GetUserTraffic is O(users), not O(connections)
//   - No Snapshot/pending buffer needed
//   - No per-connection map lock contention
//   - Bytes are counted directly into per-user atomics via CountFunc callbacks
//
// The per-connection wrapper (trackedConn) is still needed for:
//   - Hooking into sing's ReadCounter/WriteCounter for zero-copy byte counting
//   - Close callback to decrement IP refcounts
//   - Per-connection rate limit token accumulation (amortized WaitN)
//
// connRef holds a closable connection plus the user it belongs to, so the
// tracker can force-close either a single connection (by ID) or every
// connection of a user (by UUID). Both net.Conn and N.PacketConn satisfy
// io.Closer, so this covers TCP and UDP.
type connRef struct {
	closer io.Closer
	userID int
}

type ConnTracker struct {
	usersMu sync.RWMutex
	users   map[int]*userStats // userID → stats
	uuidMap map[string]int     // UUID → userID (for lookup in RoutedConnection)
	connMap map[string]connRef // connID → conn ref (for force-close support)

	idCounter atomic.Int64

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	speedLimitFunc atomic.Pointer[func(uuid string) *rate.Limiter]

	// deviceLimitFunc resolves a user UUID to their device limit.
	deviceLimitFunc atomic.Pointer[func(uuid string) (int, bool)]

	// aclFunc resolves a user UUID to their destination policy.
	aclFunc    atomic.Pointer[func(uuid string) *acl.Policy]
	aclDenials atomic.Uint64

	// Multi-node device state from panel
	globalDevices    map[int]map[string]bool // userID → IP → exists
	globalMu         sync.RWMutex
	globalLastUpdate time.Time

	// Access logging (per-connection domain/dest capture). Off by default.
	accessEnabled atomic.Bool
	accessMu      sync.Mutex
	accessBuf     []model.AccessRecord
	accessDropped atomic.Int64
}

// SetAccessLogEnabled toggles per-connection access logging.
func (t *ConnTracker) SetAccessLogEnabled(enabled bool) {
	t.accessEnabled.Store(enabled)
}

// recordAccess appends one access record, dropping (counted) when the buffer is full.
func (t *ConnTracker) recordAccess(r model.AccessRecord) {
	t.accessMu.Lock()
	if len(t.accessBuf) >= accessBufMax {
		t.accessMu.Unlock()
		if n := t.accessDropped.Add(1); n%1000 == 1 {
			nlog.Core().Warn("access log buffer full, dropping records", "dropped", n)
		}
		return
	}
	t.accessBuf = append(t.accessBuf, r)
	t.accessMu.Unlock()
}

// DrainAccessLog returns and clears all buffered access records.
func (t *ConnTracker) DrainAccessLog() []model.AccessRecord {
	t.accessMu.Lock()
	out := t.accessBuf
	t.accessBuf = nil
	t.accessMu.Unlock()
	return out
}

// emitAccess builds a record from a finished TCP connection (called on Close).
func (t *ConnTracker) emitAccess(c *trackedConn) {
	if !t.accessEnabled.Load() || c == nil || c.destHost == "" || c.us == nil {
		return
	}
	t.recordAccess(model.AccessRecord{
		Time:       time.Now().UnixMilli(),
		UserID:     c.userID,
		SourceIP:   c.sourceIP,
		DestHost:   c.destHost,
		DestPort:   c.destPort,
		Network:    "tcp",
		Upload:     c.connUp.Load(),
		Download:   c.connDown.Load(),
		DurationMs: time.Since(c.startAt).Milliseconds(),
		Reason:     derefStr(c.failReason.Load()),
	})
}

// emitAccessPacket builds a record from a finished UDP connection (called on Close).
func (t *ConnTracker) emitAccessPacket(c *trackedPacketConn) {
	if !t.accessEnabled.Load() || c == nil || c.destHost == "" || c.us == nil {
		return
	}
	t.recordAccess(model.AccessRecord{
		Time:       time.Now().UnixMilli(),
		UserID:     c.userID,
		SourceIP:   c.sourceIP,
		DestHost:   c.destHost,
		DestPort:   c.destPort,
		Network:    "udp",
		Upload:     c.connUp.Load(),
		Download:   c.connDown.Load(),
		DurationMs: time.Since(c.startAt).Milliseconds(),
		Reason:     derefStr(c.failReason.Load()),
	})
}

// cleanReason 去掉 sing 包裹的 "open connection to X using outbound/Y]: " 前缀，
// 只保留核心错误，并截断长度。
func cleanReason(s string) string {
	if i := strings.Index(s, "]: "); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func ptrStr(s string) *string { return &s }

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// destFromMeta extracts the requested target (domain preferred, else IP) and port.
func destFromMeta(metadata adapter.InboundContext) (string, int) {
	host := metadata.Destination.Fqdn
	if host == "" && metadata.Destination.Addr.IsValid() {
		host = metadata.Destination.Addr.String()
	}
	return host, int(metadata.Destination.Port)
}

// NewConnTracker creates a tracker.
func NewConnTracker(_ int) *ConnTracker {
	return &ConnTracker{
		users:         make(map[int]*userStats),
		uuidMap:       make(map[string]int),
		connMap:       make(map[string]connRef),
		globalDevices: make(map[int]map[string]bool),
	}
}

// SetSpeedLimitFunc configures the per-user speed limit lookup.
func (t *ConnTracker) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	t.speedLimitFunc.Store(&fn)
}

// SetDeviceLimitFunc configures the per-user device limit lookup for gate-keeping.
func (t *ConnTracker) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	t.deviceLimitFunc.Store(&fn)
}

// SetACLFunc configures the per-user destination policy lookup. Passing nil
// disables ACL checks.
func (t *ConnTracker) SetACLFunc(fn func(uuid string) *acl.Policy) {
	if fn == nil {
		t.aclFunc.Store(nil)
		return
	}
	t.aclFunc.Store(&fn)
}

// ACLDenials returns the number of connections the ACL rejected (or would
// have rejected, in dry-run) since this tracker was created.
func (t *ConnTracker) ACLDenials() uint64 { return t.aclDenials.Load() }

// aclRejects reports whether the user's policy forbids this destination, and
// records the denial for the panel either way.
//
// sing-box calls the tracker after routing has picked an outbound, so the
// only way to refuse is to close the connection. That is the same mechanism
// the device-limit gate already uses.
func (t *ConnTracker) aclRejects(uuid string, userID int, sourceIP string, metadata adapter.InboundContext, udp bool) bool {
	fn := t.aclFunc.Load()
	if fn == nil {
		return false
	}
	policy := (*fn)(uuid)
	if !policy.Restricted() {
		return false
	}

	dest := acl.Dest{Port: metadata.Destination.Port, UDP: udp}
	if fqdn := metadata.Destination.Fqdn; fqdn != "" {
		dest.Domain = strings.ToLower(fqdn)
		// A `resolve` route action does not rewrite Destination — it only fills
		// DestinationAddresses (sing-box route.actionResolve) — so this is the
		// one place the node's own resolution of the name is visible. Without
		// it an ip_cidr rule can never govern domain-addressed traffic, which
		// is most of it: clients hand us the hostname, not an address.
		dest.ResolvedIPs = metadata.DestinationAddresses
	} else if addr := metadata.Destination.Addr; addr.IsValid() {
		dest.IP = addr.Unmap()
	}

	action, origin := policy.Evaluate(dest)
	if action == acl.ActionAllow {
		return false
	}

	t.aclDenials.Add(1)
	t.recordACLDenial(userID, sourceIP, metadata, udp, policy, origin)

	if policy.DryRun() {
		nlog.Core().Info("singbox: acl would deny (dryrun)",
			"user", uuid, "dest", metadata.Destination.String(), "rule", origin)
		return false
	}
	nlog.Core().Debug("singbox: acl denied",
		"user", uuid, "dest", metadata.Destination.String(), "rule", origin)
	return true
}

// recordACLDenial buffers an ACL verdict for the next panel push.
//
// Deliberately not gated on accessEnabled: an operator running dry-run needs
// the impact report without also turning on full access logging.
func (t *ConnTracker) recordACLDenial(userID int, sourceIP string, metadata adapter.InboundContext,
	udp bool, policy *acl.Policy, origin string) {
	host, port := destFromMeta(metadata)
	network := "tcp"
	if udp {
		network = "udp"
	}
	t.recordAccess(model.AccessRecord{
		Time:      time.Now().UnixMilli(),
		UserID:    userID,
		SourceIP:  sourceIP,
		DestHost:  host,
		DestPort:  port,
		Network:   network,
		ACLMode:   policy.ModeLabel(),
		ACLAction: acl.ActionDeny.String(),
		ACLRule:   origin,
	})
}

// SetUserMap replaces the UUID→userID mapping and ensures per-user stats
// structs exist for all users. Old users that are no longer present keep
// their stats until their connections drain.
func (t *ConnTracker) SetUserMap(m map[string]int) {
	t.usersMu.Lock()
	t.uuidMap = m
	for _, uid := range m {
		if _, ok := t.users[uid]; !ok {
			t.users[uid] = &userStats{ips: make(map[string]int)}
		}
	}
	t.usersMu.Unlock()
}

// UpdateGlobalDevices syncs global device state from panel.
func (t *ConnTracker) UpdateGlobalDevices(users map[int][]string) {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		m := make(map[string]bool, len(ips))
		for _, ip := range ips {
			m[ip] = true
		}
		t.globalDevices[uid] = m
	}
	t.globalLastUpdate = time.Now()
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state updated", "users", len(users))
}

// ClearGlobalDevices resets global device state (on WS disconnect).
func (t *ConnTracker) ClearGlobalDevices() {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool)
	t.globalLastUpdate = time.Time{}
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state cleared")
}

// ─── adapter.ConnectionTracker ──────────────────────────────────────────────

// RoutedConnection wraps a TCP conn to count bytes per-user, track IPs,
// and optionally rate-limit. Gate-keeps device limits at connection time.
func (t *ConnTracker) RoutedConnection(
	ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()

	// ACL first: a forbidden destination should not burn a device slot.
	if t.aclRejects(uuid, uid, sourceIP, metadata, false) {
		conn.Close()
		return conn
	}

	// Device limit gate-keeping
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			if t.checkDeviceGate(us, uid, sourceIP, limit) {
				nlog.Core().Info("singbox: device limit gate-keep, rejecting connection",
					"user", uuid, "ip", sourceIP, "limit", limit)
				conn.Close()
				return conn
			}
		}
	}

	// Register connection
	if us != nil {
		us.addConn(sourceIP)
	}

	connID := t.nextID()

	// Store conn reference for force-close support
	t.usersMu.Lock()
	t.connMap[connID] = connRef{closer: conn, userID: uid}
	t.usersMu.Unlock()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	tc := &trackedConn{
		Conn:     conn,
		tracker:  t,
		us:       us,
		userID:   uid,
		connID:   connID,
		sourceIP: sourceIP,
		limiter:  lim,
		ctx:      ctx,
	}
	// 仅在开启访问日志时才提取目标/记录起始时间，关闭时无额外开销
	if t.accessEnabled.Load() {
		tc.destHost, tc.destPort = destFromMeta(metadata)
		tc.startAt = time.Now()
	}
	return tc
}

// RoutedPacketConnection wraps UDP with per-user counting and registers the
// packet conn in connMap so it can be force-closed by ID or by user UUID
// (N.PacketConn satisfies io.Closer). trackedPacketConn.Close removes the ref.
func (t *ConnTracker) RoutedPacketConnection(
	ctx context.Context, conn N.PacketConn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()

	// ACL first: a forbidden destination should not burn a device slot.
	if t.aclRejects(uuid, uid, sourceIP, metadata, true) {
		conn.Close()
		return conn
	}

	// Device limit gate-keeping
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			if t.checkDeviceGate(us, uid, sourceIP, limit) {
				nlog.Core().Info("singbox: device limit gate-keep, rejecting UDP connection",
					"user", uuid, "ip", sourceIP, "limit", limit)
				conn.Close()
				return conn
			}
		}
	}

	if us != nil {
		us.addConn(sourceIP)
	}

	connID := t.nextID()

	// Store conn reference for force-close support (TCP + UDP).
	t.usersMu.Lock()
	t.connMap[connID] = connRef{closer: conn, userID: uid}
	t.usersMu.Unlock()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	tc := &trackedPacketConn{
		PacketConn: conn,
		tracker:    t,
		us:         us,
		userID:     uid,
		connID:     connID,
		sourceIP:   sourceIP,
		limiter:    lim,
		ctx:        ctx,
	}
	if t.accessEnabled.Load() {
		tc.destHost, tc.destPort = destFromMeta(metadata)
		tc.startAt = time.Now()
	}
	return tc
}

// checkDeviceGate rejects connections exceeding device limit.
// Strategy: merge local + global state when fresh; local-only when stale.
func (t *ConnTracker) checkDeviceGate(us *userStats, userID int, sourceIP string, limit int) bool {
	if us == nil || limit <= 0 {
		return false
	}

	us.mu.RLock()
	localIPs := make(map[string]bool, len(us.ips))
	for ip := range us.ips {
		localIPs[ip] = true
	}
	localCount := len(us.ips)
	us.mu.RUnlock()

	// Already known locally
	if localIPs[sourceIP] {
		return false
	}

	// Check global state freshness
	t.globalMu.RLock()
	globalStale := time.Since(t.globalLastUpdate) > 60*time.Second
	globalIPs := t.globalDevices[userID]
	t.globalMu.RUnlock()

	// Stale or missing global state → local-only check
	if globalStale || globalIPs == nil {
		if localCount < limit {
			return false
		}
		ipList := make([]string, 0, localCount+1)
		for ip := range localIPs {
			ipList = append(ipList, ip)
		}
		ipList = append(ipList, sourceIP)
		sort.Strings(ipList)
		for i := 0; i < limit && i < len(ipList); i++ {
			if ipList[i] == sourceIP {
				return false
			}
		}
		nlog.Core().Debug("device limit: local over limit, rejecting",
			"userID", userID, "ip", sourceIP, "localIPs", localCount, "limit", limit)
		return true
	}

	// Known globally (from other node)
	if globalIPs[sourceIP] {
		return false
	}

	// Merge local + global
	allIPs := make(map[string]bool)
	for ip := range localIPs {
		allIPs[ip] = true
	}
	for ip := range globalIPs {
		allIPs[ip] = true
	}

	if len(allIPs) < limit {
		return false
	}

	// Over limit → lexicographic selection
	ipList := make([]string, 0, len(allIPs)+1)
	for ip := range allIPs {
		ipList = append(ipList, ip)
	}
	ipList = append(ipList, sourceIP)
	sort.Strings(ipList)

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i] == sourceIP {
			return false
		}
	}
	nlog.Core().Debug("device limit: total over limit, rejecting",
		"userID", userID, "ip", sourceIP, "totalIPs", len(allIPs), "limit", limit)
	return true
}

func (t *ConnTracker) nextID() string {
	return "sb-" + formatInt36(t.idCounter.Add(1))
}

func formatInt36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [13]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	return string(buf[i:])
}

// ─── Public API ─────────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic and alive IPs.
// This is O(users), not O(connections).
func (t *ConnTracker) GetUserTraffic() (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int) {
	t.usersMu.RLock()
	traffic = make(map[int][2]int64, len(t.users))
	aliveIPs = make(map[int]map[string]bool, len(t.users))
	for uid, us := range t.users {
		up := us.upload.Load()
		down := us.download.Load()
		if up > 0 || down > 0 {
			traffic[uid] = [2]int64{up, down}
		}

		ips := us.aliveIPList()
		if ips != nil {
			aliveIPs[uid] = ips
		}

		us.mu.Lock()
		connCount += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return
}

// GetUserConnCounts returns per-user active connection counts (only users with
// at least one connection). O(users). Useful for spotting connection-flood
// abuse that a bytes/sec view alone would miss.
func (t *ConnTracker) GetUserConnCounts() map[int]int {
	t.usersMu.RLock()
	defer t.usersMu.RUnlock()
	out := make(map[int]int, len(t.users))
	for uid, us := range t.users {
		us.mu.Lock()
		c := us.connCount
		us.mu.Unlock()
		if c > 0 {
			out[uid] = c
		}
	}
	return out
}

// CloseByID force-closes a connection by its ID.
func (t *ConnTracker) CloseByID(id string) bool {
	t.usersMu.RLock()
	ref, ok := t.connMap[id]
	t.usersMu.RUnlock()
	if !ok {
		return false
	}
	if ref.closer != nil {
		ref.closer.Close()
	}
	return true
}

// CloseByUUID force-closes ALL active connections (TCP + UDP) for a given
// user UUID and returns the number of connections it closed. It closes the
// underlying socket, which makes the next I/O fail; sing-box then tears down
// the wrapper, whose Close() is what actually removes the connMap entry and
// releases the IP/conn refcounts. Cleanup is therefore asynchronous — the
// returned count reflects sockets closed now, not entries already removed, and
// a repeated call in the teardown window may re-close (harmlessly) the same
// sockets.
func (t *ConnTracker) CloseByUUID(uuid string) int {
	t.usersMu.RLock()
	uid, ok := t.uuidMap[uuid]
	if !ok {
		t.usersMu.RUnlock()
		return 0
	}
	// Snapshot the matching closers under the read lock, then Close() them
	// after releasing it: Close can block on network teardown, and we must not
	// hold usersMu (also taken by RoutedConnection and removeConnRef) meanwhile.
	closers := make([]io.Closer, 0, 8)
	for _, ref := range t.connMap {
		if ref.userID == uid && ref.closer != nil {
			closers = append(closers, ref.closer)
		}
	}
	t.usersMu.RUnlock()

	for _, c := range closers {
		c.Close()
	}
	return len(closers)
}

// ActiveCount returns the total number of active connections.
func (t *ConnTracker) ActiveCount() int {
	t.usersMu.RLock()
	total := 0
	for _, us := range t.users {
		us.mu.Lock()
		total += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return total
}

// removeConnRef removes the connection reference from connMap on close.
func (t *ConnTracker) removeConnRef(connID string) {
	t.usersMu.Lock()
	delete(t.connMap, connID)
	t.usersMu.Unlock()
}

// ─── trackedConn (TCP) ──────────────────────────────────────────────────────

// RateLimitedWriter wraps a Writer with non-blocking rate limiting.
// Uses AllowN for instant checks and context-aware waiting when needed.
type RateLimitedWriter struct {
	writer  io.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

// Write implements io.Writer with rate limiting.
func (w *RateLimitedWriter) Write(b []byte) (int, error) {
	// Truncate to burst size
	if burst := w.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	// Fast path: check if tokens available (non-blocking)
	if w.limiter.AllowN(time.Now(), len(b)) {
		return w.writer.Write(b)
	}

	// Slow path: wait for tokens with context cancellation support
	resv := w.limiter.ReserveN(time.Now(), len(b))
	if delay := resv.Delay(); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			// Tokens available, proceed
		case <-w.ctx.Done():
			resv.Cancel()
			return 0, w.ctx.Err()
		}
	}

	return w.writer.Write(b)
}

// RateLimitedReadCloser wraps a Reader with non-blocking rate limiting.
type RateLimitedReadCloser struct {
	reader  io.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

// Read implements io.Reader with rate limiting.
func (r *RateLimitedReadCloser) Read(b []byte) (int, error) {
	// Truncate to burst size
	if burst := r.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	n, err := r.reader.Read(b)
	if n > 0 && r.limiter != nil {
		// Fast path: check if tokens available
		if !r.limiter.AllowN(time.Now(), n) {
			// Slow path: wait with context cancellation
			resv := r.limiter.ReserveN(time.Now(), n)
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-r.ctx.Done():
					resv.Cancel()
					return n, r.ctx.Err()
				}
			}
		}
	}
	return n, err
}

type trackedConn struct {
	net.Conn
	tracker  *ConnTracker
	us       *userStats // per-user stats (upload/download atomics + IP tracking)
	userID   int        // user ID for device tracking
	connID   string
	sourceIP string
	limiter  *rate.Limiter
	ctx      context.Context
	closed   atomic.Bool

	// access logging (per-connection)
	destHost   string
	destPort   int
	startAt    time.Time
	connUp     atomic.Int64
	connDown   atomic.Int64
	failReason atomic.Pointer[string] // 出站拨号失败原因（sing 经 HandshakeFailure 回调写入）
}

func (c *trackedConn) Read(b []byte) (int, error) {
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		if c.us != nil {
			c.us.upload.Add(int64(n)) // 从入站读取 = 用户上传
		}
		c.connUp.Add(int64(n))
		if c.limiter != nil {
			// Non-blocking rate limiting
			if !c.limiter.AllowN(time.Now(), n) {
				resv := c.limiter.ReserveN(time.Now(), n)
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return n, c.ctx.Err()
					}
				}
			}
		}
	}
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	// Apply rate limiting before write
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
		// Non-blocking check first
		if !c.limiter.AllowN(time.Now(), len(b)) {
			resv := c.limiter.ReserveN(time.Now(), len(b))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return 0, c.ctx.Err()
				}
			}
		}
	}

	n, err := c.Conn.Write(b)
	if n > 0 {
		if c.us != nil {
			c.us.download.Add(int64(n)) // 向入站写入 = 用户下载
		}
		c.connDown.Add(int64(n))
	}
	return n, err
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.connID)
		c.tracker.emitAccess(c)
	}
	return c.Conn.Close()
}

// makeCountFunc builds a CountFunc for zero-copy byte counting via sing's
// ReadCounter/WriteCounter unwrap interfaces.
func (c *trackedConn) makeCountFunc(counter, connCounter *atomic.Int64) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) { counter.Add(n); connCounter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		connCounter.Add(n)
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.upload, &c.connUp)} // 从入站读取 = 用户上传
}

func (c *trackedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.download, &c.connDown)} // 向入站写入 = 用户下载
}

func (c *trackedConn) Upstream() any           { return c.Conn }
func (c *trackedConn) ReaderReplaceable() bool { return true }
func (c *trackedConn) WriterReplaceable() bool { return true }

// HandshakeFailure 由 sing 的 N.CloseOnHandshakeFailure 在出站拨号失败时回调，
// 携带真实错误（connection refused / i/o timeout / 域名解析失败 等）。
// 记录原因后转发给内层连接，保留各入站协议自身的失败响应行为。
func (c *trackedConn) HandshakeFailure(err error) error {
	if err != nil {
		c.failReason.Store(ptrStr(cleanReason(err.Error())))
	}
	return N.ReportHandshakeFailure(c.Conn, err)
}

// ─── trackedPacketConn (UDP / QUIC) ─────────────────────────────────────────

type trackedPacketConn struct {
	N.PacketConn
	tracker  *ConnTracker
	us       *userStats
	userID   int
	connID   string
	sourceIP string
	limiter  *rate.Limiter
	ctx      context.Context
	closed   atomic.Bool

	// access logging (per-connection)
	destHost   string
	destPort   int
	startAt    time.Time
	connUp     atomic.Int64
	connDown   atomic.Int64
	failReason atomic.Pointer[string]
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (singM.Socksaddr, error) {
	dest, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		n := int64(buffer.Len())
		if c.us != nil {
			c.us.upload.Add(n) // 从入站读取 = 用户上传
		}
		c.connUp.Add(n)
		if c.limiter != nil {
			// Non-blocking rate limiting with context cancellation
			if !c.limiter.AllowN(time.Now(), int(n)) {
				resv := c.limiter.ReserveN(time.Now(), int(n))
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return dest, c.ctx.Err()
					}
				}
			}
		}
	}
	return dest, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, dest singM.Socksaddr) error {
	n := int64(buffer.Len())

	// Apply rate limiting before write
	if c.limiter != nil {
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return c.ctx.Err()
				}
			}
		}
	}

	err := c.PacketConn.WritePacket(buffer, dest)
	if err == nil {
		if c.us != nil {
			c.us.download.Add(n) // 向入站写入 = 用户下载
		}
		c.connDown.Add(n)
	}
	return err
}

func (c *trackedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.connID)
		c.tracker.emitAccessPacket(c)
	}
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) makeCountFunc(counter, connCounter *atomic.Int64) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) { counter.Add(n); connCounter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		connCounter.Add(n)
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedPacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.download, &c.connDown)}
}

func (c *trackedPacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.upload, &c.connUp)}
}

func (c *trackedPacketConn) Upstream() any           { return c.PacketConn }
func (c *trackedPacketConn) ReaderReplaceable() bool { return true }
func (c *trackedPacketConn) WriterReplaceable() bool { return true }

func (c *trackedPacketConn) HandshakeFailure(err error) error {
	if err != nil {
		c.failReason.Store(ptrStr(cleanReason(err.Error())))
	}
	return N.ReportHandshakeFailure(c.PacketConn, err)
}
