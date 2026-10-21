// Package machine implements the machine-mode orchestrator that dynamically
// discovers nodes from the panel's machine API and manages their lifecycles.
package machine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/localstats"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/monitor"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/cedar2025/xboard-node/internal/service"
)

// nodeHandle tracks a running node service.
type nodeHandle struct {
	cancel  context.CancelFunc
	done    chan struct{}
	mailbox *controlplane.NodeMailbox
}

// Orchestrator manages all nodes bound to a panel machine. It:
//   - discovers nodes via GET /machine/nodes
//   - starts / stops Service instances as nodes are added / removed
//   - maintains a shared WS connection that demuxes events by node_id
//   - reports machine-level load via POST /machine/status
type Orchestrator struct {
	cfg    *config.Config
	client *panel.Client // machine-level client (no node_id)

	mu    sync.Mutex
	nodes map[int]*nodeHandle // node_id → handle
	// wanted is the latest node list from the panel; retry holds nodes whose
	// service exited with an error and are waiting to be restarted.
	wanted map[int]panel.MachineNode
	retry  map[int]*nodeRetry

	// Per-node mailbox keyed by node_id. Shared WS events are aggregated here
	// and each node service drains the latest state when ready.
	eventsMu  sync.RWMutex
	mailboxes map[int]*controlplane.NodeMailbox
	statuses  map[int]chan<- controlplane.StatusChange

	// Shared WS client (nil when WS is disabled).
	ws       *panel.WSClient
	wsCancel context.CancelFunc

	// runCtx is stored from Run() so that onWSEvent can trigger rediscover
	// for sync.nodes events without blocking the main loop.
	runCtx context.Context

	pullInterval time.Duration
	pushInterval time.Duration

	// Local stats endpoint: outcome of node discovery / machine status calls.
	statDiscovery localstats.ConnStat
	statStatus    localstats.ConnStat
}

// New creates a machine orchestrator from the given config.
func New(cfg *config.Config) *Orchestrator {
	panelCfg := config.PanelConfig{
		URL:       cfg.Panel.URL,
		Token:     cfg.Machine.Token,
		MachineID: cfg.Machine.MachineID,
	}
	return &Orchestrator{
		cfg:       cfg,
		client:    panel.NewClient(panelCfg),
		nodes:     make(map[int]*nodeHandle),
		wanted:    make(map[int]panel.MachineNode),
		retry:     make(map[int]*nodeRetry),
		mailboxes: make(map[int]*controlplane.NodeMailbox),
		statuses:  make(map[int]chan<- controlplane.StatusChange),
	}
}

// Run is the main loop. It blocks until ctx is cancelled.
func (o *Orchestrator) Run(ctx context.Context) error {
	o.runCtx = ctx
	nodesResp, err := o.client.GetMachineNodes()
	if err != nil {
		return fmt.Errorf("initial node discovery: %w", err)
	}
	o.statDiscovery.OK()

	o.applyIntervals(nodesResp.BaseConfig)
	o.applyAgentTarget(nodesResp.Agent)
	nlog.Core().Info(fmt.Sprintf("machine %d: discovered %d nodes",
		o.cfg.Machine.MachineID, len(nodesResp.Nodes)))

	// Start machine-level WS as early as possible so sync.nodes can reach an
	// empty machine before the first node is attached.
	o.tryStartWS(ctx)
	// After tryStartWS: o.ws is only written there, before the sampler can read it.
	defer localstats.RegisterMachine(o)()

	// Start initial nodes.
	o.setWanted(nodesResp.Nodes)
	for _, n := range nodesResp.Nodes {
		o.startNode(ctx, n)
	}

	discoveryTicker := time.NewTicker(o.pullInterval)
	statusTicker := time.NewTicker(o.pushInterval)
	defer discoveryTicker.Stop()
	defer statusTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			o.stopAll()
			return nil

		case <-discoveryTicker.C:
			o.rediscover(ctx)

		case <-statusTicker.C:
			o.reportMachineStatus()
		}
	}
}

// ─── Node lifecycle ──────────────────────────────────────────────────────

func (o *Orchestrator) startNode(ctx context.Context, mn panel.MachineNode) {
	o.mu.Lock()
	if _, exists := o.nodes[mn.ID]; exists {
		o.mu.Unlock()
		return
	}
	if r := o.retry[mn.ID]; r != nil && time.Now().Before(r.next) {
		o.mu.Unlock()
		return // failed recently; the retry timer will start it
	}

	nodeCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	mb := controlplane.NewNodeMailbox()
	h := &nodeHandle{cancel: cancel, done: done, mailbox: mb}
	o.nodes[mn.ID] = h
	o.mu.Unlock()

	o.eventsMu.Lock()
	o.mailboxes[mn.ID] = mb
	o.eventsMu.Unlock()

	nodeCfg := o.cfg.ExpandMachineNode(mn.ID, mn.Type)

	perNodeClient := o.client.ForNode(mn.ID)

	// Pre-fetch node config to detect transport-based kernel requirements.
	// If the transport (e.g. xhttp) is incompatible with the configured kernel
	// (e.g. singbox), auto-switch to the required kernel for this node.
	if cfgSnapshot, err := perNodeClient.GetConfig(); err == nil && cfgSnapshot != nil {
		if resolved := model.ResolveKernelForTransport(cfgSnapshot.Network, nodeCfg.Kernel.Type); resolved != nodeCfg.Kernel.Type {
			nlog.Core().Info(fmt.Sprintf("machine: auto-switching kernel for node %d (%s→%s, transport=%s)",
				mn.ID, nodeCfg.Kernel.Type, resolved, cfgSnapshot.Network))
			nodeCfg.Kernel.Type = resolved
		}
	}
	// Reset cached ETag so the subsequent GetConfig in Initial() gets a full response.
	perNodeClient.ResetConfigETag()

	var push controlplane.PushClient
	if o.ws != nil {
		push = &machineNodePush{
			nodeID: mn.ID,
			ws:     o.ws,
		}
	}

	// The registerFn is called by MachinePanelControlPlane.Initial() to expose
	// the node mailbox + status channel to the Service.
	nodeID := mn.ID
	registerFn := func(st chan<- controlplane.StatusChange) *controlplane.NodeMailbox {
		o.registerNode(nodeID, st)
		return mb
	}

	cp := controlplane.NewMachinePanelControlPlane(perNodeClient, nodeCfg.Kernel, push, registerFn)
	svc := service.NewWithControlPlane(nodeCfg, cp)

	nlog.Core().Info(fmt.Sprintf("machine: starting node %d (%s/%s)",
		mn.ID, mn.Type, mn.Name))

	go func() {
		started := time.Now()
		err := svc.Run(nodeCtx)
		o.unregisterNode(mn.ID)
		close(done)
		if err == nil || nodeCtx.Err() != nil {
			return // stopped on purpose
		}
		// The node died on its own (e.g. its port is taken, kernel failed to start).
		// Without this it stayed in o.nodes forever and was never started again.
		delay := o.nodeFailed(ctx, mn.ID, h, started, err)
		nlog.Core().Error("machine node exited with error",
			"node_id", mn.ID, "error", err, "retry_in", delay.String())
	}()
}

// ─── Restart of failed nodes ─────────────────────────────────────────────

const (
	nodeRetryMin    = 10 * time.Second
	nodeRetryMax    = 5 * time.Minute
	nodeRetryStable = 10 * time.Minute // ran this long → earlier failures are forgotten
)

type nodeRetry struct {
	attempts int
	next     time.Time
	lastErr  string    // why the last start failed (shown by the local stats endpoint)
	lastExit time.Time // when it failed
}

// retryDelay is the wait before restart attempt n (n ≥ 1): 10s, 20s, 40s … capped at 5m.
func retryDelay(n int) time.Duration {
	d := nodeRetryMin
	for i := 1; i < n && d < nodeRetryMax; i++ {
		d *= 2
	}
	if d > nodeRetryMax {
		d = nodeRetryMax
	}
	return d
}

// nodeFailed forgets the dead handle and schedules a restart with backoff.
func (o *Orchestrator) nodeFailed(ctx context.Context, id int, h *nodeHandle, started time.Time, cause error) time.Duration {
	o.mu.Lock()
	if o.nodes[id] == h {
		delete(o.nodes, id)
	}
	r := o.retry[id]
	if r == nil || time.Since(started) >= nodeRetryStable {
		r = &nodeRetry{}
		o.retry[id] = r
	}
	r.attempts++
	if cause != nil {
		r.lastErr = cause.Error()
	}
	r.lastExit = time.Now()
	n := r.attempts
	delay := retryDelay(n)
	r.next = time.Now().Add(delay)
	o.mu.Unlock()

	time.AfterFunc(delay, func() {
		if ctx.Err() != nil {
			return
		}
		o.mu.Lock()
		mn, ok := o.wanted[id]
		if !ok {
			delete(o.retry, id) // removed from the panel meanwhile
		}
		o.mu.Unlock()
		if ok {
			nlog.Core().Info(fmt.Sprintf("machine: restarting node %d after failure (attempt %d)", id, n))
			o.startNode(ctx, mn)
		}
	})
	return delay
}

// setWanted records the panel's current node list and drops retry state for
// nodes that are gone.
func (o *Orchestrator) setWanted(nodes []panel.MachineNode) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.wanted = make(map[int]panel.MachineNode, len(nodes))
	for _, n := range nodes {
		o.wanted[n.ID] = n
	}
	for id := range o.retry {
		if _, ok := o.wanted[id]; !ok {
			delete(o.retry, id)
		}
	}
}

func (o *Orchestrator) stopNode(nodeID int) {
	o.mu.Lock()
	h, ok := o.nodes[nodeID]
	if !ok {
		o.mu.Unlock()
		return
	}
	delete(o.nodes, nodeID)
	o.mu.Unlock()

	o.eventsMu.Lock()
	delete(o.mailboxes, nodeID)
	o.eventsMu.Unlock()

	nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", nodeID))
	h.cancel()
	<-h.done
}

func (o *Orchestrator) stopAll() {
	o.mu.Lock()
	handles := make(map[int]*nodeHandle, len(o.nodes))
	for id, h := range o.nodes {
		handles[id] = h
	}
	o.mu.Unlock()

	for id, h := range handles {
		nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", id))
		h.cancel()
	}
	for _, h := range handles {
		<-h.done
	}

	if o.wsCancel != nil {
		o.wsCancel()
	}
}

// ─── Node discovery ──────────────────────────────────────────────────────

func (o *Orchestrator) rediscover(ctx context.Context) {
	nodesResp, err := o.client.GetMachineNodes()
	if err != nil {
		nlog.Core().Warn("machine node discovery failed", "error", err)
		o.statDiscovery.Fail(err)
		return
	}
	o.statDiscovery.OK()

	o.setWanted(nodesResp.Nodes)
	wanted := make(map[int]panel.MachineNode, len(nodesResp.Nodes))
	for _, n := range nodesResp.Nodes {
		wanted[n.ID] = n
	}

	o.mu.Lock()
	var toRemove []int
	for id := range o.nodes {
		if _, ok := wanted[id]; !ok {
			toRemove = append(toRemove, id)
		}
	}
	o.mu.Unlock()

	for _, id := range toRemove {
		o.stopNode(id)
	}

	for _, n := range nodesResp.Nodes {
		o.startNode(ctx, n) // no-op if already running
	}
	o.applyAgentTarget(nodesResp.Agent)
}

// applyAgentTarget 按面板下发的目标版本触发自更新。
//
// 节点侧也有一条同样的路径（访问日志回传里的 update.to），但那条路要求这台机器
// **至少跑着一个节点**：面板上新建的机器、或节点全被停用的机器，只有这条通道能升级。
// service.TriggerSelfUpdate 是进程级互斥的，两条路同时命中也只会升一次。
func (o *Orchestrator) applyAgentTarget(target *panel.AgentTarget) {
	if target == nil || target.TargetVersion == "" {
		return
	}
	if target.TargetVersion == service.Version() {
		return
	}
	service.TriggerSelfUpdate(target.TargetVersion)
}

// ─── Machine status reporting ────────────────────────────────────────────

func (o *Orchestrator) reportMachineStatus() {
	s := monitor.Collect()
	if err := o.client.ReportMachineStatus(
		s.CPU,
		[2]uint64{s.MemTotal, s.MemUsed},
		[2]uint64{s.SwapTotal, s.SwapUsed},
		[2]uint64{s.DiskTotal, s.DiskUsed},
		s.NetInSpeed, s.NetOutSpeed,
		service.Version(),
	); err != nil {
		nlog.Core().Warn("machine status report failed", "error", err)
		o.statStatus.Fail(err)
		return
	}
	o.statStatus.OK()
}

// StatsMachineView implements localstats.MachineSource (sampled every 10 s
// when the local stats endpoint is enabled).
func (o *Orchestrator) StatsMachineView() localstats.MachineView {
	v := localstats.MachineView{
		ID:        o.cfg.Machine.MachineID,
		Panel:     panelHost(o.cfg.Panel.URL),
		WS:        -1,
		Discovery: o.statDiscovery.Snapshot(),
		Status:    o.statStatus.Snapshot(),
	}
	o.mu.Lock()
	for id, mn := range o.wanted {
		n := localstats.MachineNode{ID: id, Name: mn.Name, Type: mn.Type}
		_, n.Running = o.nodes[id]
		if r := o.retry[id]; r != nil {
			n.Attempts, n.NextRetry, n.LastError = r.attempts, r.next.Unix(), r.lastErr
			if !r.lastExit.IsZero() {
				n.LastExit = r.lastExit.Unix()
			}
		}
		v.Nodes = append(v.Nodes, n)
	}
	o.mu.Unlock()
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].ID < v.Nodes[j].ID })
	if ws := o.ws; ws != nil {
		v.WS = 0
		if ws.IsConnected() {
			v.WS = 1
		}
	}
	return v
}

// panelHost keeps only the host of the panel URL (no path, query or token).
func panelHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// ─── WS mux ─────────────────────────────────────────────────────────────

func (o *Orchestrator) tryStartWS(ctx context.Context) {
	hs, err := o.client.Handshake()
	if err != nil {
		nlog.Core().Warn("machine ws handshake failed, REST only", "error", err)
		return
	}
	if !hs.WebSocket.Enabled || hs.WebSocket.WSURL == "" {
		nlog.Core().Info("machine: ws disabled by panel, REST only")
		return
	}

	wsCfg := panel.WSClientConfig{
		StatusInterval:   time.Duration(o.cfg.WS.StatusInterval) * time.Second,
		HandshakeTimeout: time.Duration(o.cfg.WS.HandshakeTimeout) * time.Second,
		BackoffInitial:   time.Duration(o.cfg.WS.BackoffInitial) * time.Second,
		BackoffMax:       time.Duration(o.cfg.WS.BackoffMax) * time.Second,
		MachineID:        o.cfg.Machine.MachineID,
	}

	o.ws = panel.NewWSClient(
		hs.WebSocket.WSURL,
		o.cfg.Machine.Token,
		0, // no single node_id
		wsCfg,
		o.onWSEvent,
		o.onWSStatus,
		nil, // per-node status is sent via machineNodePush
	)

	wsCtx, wsCancel := context.WithCancel(ctx)
	o.wsCancel = wsCancel
	go o.ws.Run(wsCtx)

	nlog.Core().Info("machine: ws mux started")
}

// onWSEvent routes a WS event to the correct node's channel.
// sync.nodes is a machine-level event that triggers immediate rediscovery.
func (o *Orchestrator) onWSEvent(event panel.WSEvent) {
	// sync.nodes is a machine-level event, not per-node
	if event.Type == panel.WSEventSyncNodes {
		nlog.Core().Info("machine received sync.nodes, triggering immediate rediscovery")
		go o.rediscover(o.runCtx)
		return
	}

	nodeID := event.NodeID
	if nodeID == 0 {
		nlog.Core().Debug("machine ws event missing node_id, dropping", "type", event.Type)
		return
	}

	translated, err := controlplane.TranslateWSEvent(event, o.cfg.Kernel)
	if err != nil {
		nlog.Core().Warn("machine ws event translation failed",
			"type", event.Type, "node_id", nodeID, "error", err)
		return
	}

	o.eventsMu.RLock()
	mailbox, ok := o.mailboxes[nodeID]
	o.eventsMu.RUnlock()
	if !ok {
		nlog.Core().Debug("machine ws event for unknown node", "node_id", nodeID, "type", event.Type)
		return
	}
	mailbox.Apply(translated)
}

// onWSStatus broadcasts WS connectivity changes to all registered nodes.
func (o *Orchestrator) onWSStatus(status panel.WSStatusChange) {
	change := controlplane.StatusChange{Connected: status.Connected}
	o.eventsMu.RLock()
	defer o.eventsMu.RUnlock()
	for _, ch := range o.statuses {
		select {
		case ch <- change:
		default:
		}
	}
}

func (o *Orchestrator) registerNode(nodeID int, st chan<- controlplane.StatusChange) {
	o.eventsMu.Lock()
	o.statuses[nodeID] = st
	o.eventsMu.Unlock()
}

func (o *Orchestrator) unregisterNode(nodeID int) {
	o.eventsMu.Lock()
	delete(o.mailboxes, nodeID)
	delete(o.statuses, nodeID)
	o.eventsMu.Unlock()
}

func (o *Orchestrator) applyIntervals(bc panel.MachineBaseConfig) {
	o.pullInterval = time.Duration(bc.PullInterval) * time.Second
	if o.pullInterval < 30*time.Second {
		o.pullInterval = 60 * time.Second
	}
	o.pushInterval = time.Duration(bc.PushInterval) * time.Second
	if o.pushInterval < 10*time.Second {
		o.pushInterval = 60 * time.Second
	}
}

// ─── Virtual PushClient ─────────────────────────────────────────────────

// machineNodePush implements controlplane.PushClient for a single node
// backed by the shared machine WS connection. Events are routed by the
// WS mux directly to the Service's channels; this adapter only provides
// connectivity status and send capabilities.
type machineNodePush struct {
	nodeID int
	ws     *panel.WSClient
}

func (p *machineNodePush) Run(ctx context.Context) {
	// The shared WS mux pushes events into our channels; we just wait.
	<-ctx.Done()
}

func (p *machineNodePush) IsConnected() bool {
	return p.ws != nil && p.ws.IsConnected()
}

func (p *machineNodePush) SendDeviceReport(devices map[int][]string) {
	if p.ws == nil {
		return
	}
	payload := map[string]interface{}{
		"node_id": p.nodeID,
	}
	// Flatten into the standard format with node_id wrapper.
	strDevices := make(map[string][]string, len(devices))
	for uid, ips := range devices {
		strDevices[fmt.Sprintf("%d", uid)] = ips
	}
	payload["devices"] = strDevices
	data, _ := json.Marshal(payload)
	p.ws.SendRaw(panel.WSEventReportDevices, data)
}
