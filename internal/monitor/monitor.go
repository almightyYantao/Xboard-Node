package monitor

import (
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

var startTime = time.Now()

// minSampleInterval bounds how often the delta-based metrics (CPU busy %,
// network throughput) are actually resampled. Collect() can be called
// concurrently by multiple nodes/goroutines sharing this one process (e.g.
// machine mode, or several nodes' push/WS tickers firing close together);
// without this floor, two calls a few milliseconds apart would each see a
// near-zero jiffy/byte delta and either divide-by-near-zero or (in
// gopsutil's case) fall back to a meaningless 100%. Calls inside the window
// simply reuse the last computed value, which is correct anyway since CPU
// and host network throughput are machine-wide, not per-node, metrics.
const minSampleInterval = time.Second

func init() {
	refreshDeltaMetrics()
}

// Status holds system resource metrics
type Status struct {
	Uptime     uint64
	CPU        float64
	CPUPerCore []float64
	Load1      float64
	Load5      float64
	Load15     float64
	MemTotal   uint64
	MemUsed    uint64
	SwapTotal  uint64
	SwapUsed   uint64
	DiskTotal  uint64
	DiskUsed   uint64
	Goroutines int

	// Network speed (bytes/sec), -1 means unavailable (first sample).
	NetInSpeed  float64
	NetOutSpeed float64

	// GC metrics (process-wide)
	NumGC       uint32
	LastPauseMS float64
}

// sampleMu guards every field below. All of it belongs to a single shared
// baseline: CPU and network throughput are host-wide facts, so every caller
// in this process (one per node, potentially) should observe the exact same
// sampled value for the exact same instant rather than each computing its
// own "since my last call" delta against shared OS counters.
var (
	sampleMu       sync.Mutex
	lastSampleTime time.Time
	hasSample      bool

	lastCPUTotal   cpu.TimesStat
	lastCPUPerCore []cpu.TimesStat
	cachedCPU      float64
	cachedPerCore  []float64

	netPrevRecv  uint64
	netPrevSent  uint64
	netPrevTime  time.Time
	cachedNetIn  float64
	cachedNetOut float64
)

// skipInterface returns true for loopback and common virtual interfaces.
func skipInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"lo", "docker", "veth", "br-", "virbr", "vnet", "tun", "tap"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// cpuBusy splits a cpu.TimesStat into (total, busy) jiffy counts, mirroring
// gopsutil's own internal getAllBusy so our delta math matches its semantics.
func cpuBusy(t cpu.TimesStat) (total, busy float64) {
	total = t.Total()
	if runtime.GOOS == "linux" {
		total -= t.Guest
		total -= t.GuestNice
	}
	busy = total - t.Idle - t.Iowait
	return total, busy
}

// cpuPercentDelta computes the busy percentage between two snapshots. Unlike
// gopsutil's cpu.Percent, it never fabricates a 100% reading when the window
// is too short to show a measurable jiffy delta — it just keeps the previous
// value, which is far less misleading for a metric sampled every few seconds.
func cpuPercentDelta(prev, curr cpu.TimesStat, fallback float64) float64 {
	prevTotal, prevBusy := cpuBusy(prev)
	currTotal, currBusy := cpuBusy(curr)

	deltaTotal := currTotal - prevTotal
	if deltaTotal <= 0 {
		return fallback
	}
	deltaBusy := currBusy - prevBusy
	if deltaBusy < 0 {
		deltaBusy = 0
	}

	pct := deltaBusy / deltaTotal * 100
	if pct < 0 {
		pct = 0
	} else if pct > 100 {
		pct = 100
	}
	return pct
}

// refreshDeltaMetrics returns the current CPU busy % (overall + per-core)
// and network in/out throughput (bytes/sec), resampling the underlying OS
// counters at most once per minSampleInterval. Safe for concurrent use by
// multiple nodes/goroutines within the same process.
func refreshDeltaMetrics() (cpuPct float64, perCore []float64, netIn, netOut float64) {
	sampleMu.Lock()
	defer sampleMu.Unlock()

	now := time.Now()
	if hasSample && now.Sub(lastSampleTime) < minSampleInterval {
		return cachedCPU, append([]float64(nil), cachedPerCore...), cachedNetIn, cachedNetOut
	}

	totalTimes, cpuErr := cpu.Times(false)
	var perCoreTimes []cpu.TimesStat
	if cpuErr == nil && len(totalTimes) > 0 {
		perCoreTimes, _ = cpu.Times(true)
	} else if cpuErr != nil {
		nlog.Core().Debug("failed to get CPU times", "error", cpuErr)
	}

	counters, netErr := net.IOCounters(true)
	var totalRecv, totalSent uint64
	if netErr == nil {
		for _, c := range counters {
			if skipInterface(c.Name) {
				continue
			}
			totalRecv += c.BytesRecv
			totalSent += c.BytesSent
		}
	} else {
		nlog.Core().Debug("failed to get network counters", "error", netErr)
	}

	if !hasSample {
		hasSample = true
		lastSampleTime = now
		if cpuErr == nil && len(totalTimes) > 0 {
			lastCPUTotal = totalTimes[0]
			lastCPUPerCore = perCoreTimes
		}
		cachedCPU = 0
		cachedPerCore = make([]float64, len(perCoreTimes))
		if netErr == nil {
			netPrevRecv, netPrevSent, netPrevTime = totalRecv, totalSent, now
		}
		cachedNetIn, cachedNetOut = -1, -1
		return cachedCPU, append([]float64(nil), cachedPerCore...), cachedNetIn, cachedNetOut
	}

	if cpuErr == nil && len(totalTimes) > 0 {
		cachedCPU = cpuPercentDelta(lastCPUTotal, totalTimes[0], cachedCPU)

		if len(perCoreTimes) > 0 && len(perCoreTimes) == len(lastCPUPerCore) {
			pc := make([]float64, len(perCoreTimes))
			for i := range perCoreTimes {
				fallback := 0.0
				if i < len(cachedPerCore) {
					fallback = cachedPerCore[i]
				}
				pc[i] = cpuPercentDelta(lastCPUPerCore[i], perCoreTimes[i], fallback)
			}
			cachedPerCore = pc
		} else {
			cachedPerCore = make([]float64, len(perCoreTimes))
		}

		lastCPUTotal = totalTimes[0]
		lastCPUPerCore = perCoreTimes
	}

	if netErr == nil {
		// Measured against netPrevTime (not the shared lastSampleTime) so a
		// transient failure of one metric on a given round can never desync
		// the byte-delta from the wall-clock window it was actually measured
		// over — netPrevRecv/Sent/Time always advance together.
		netElapsed := now.Sub(netPrevTime).Seconds()
		switch {
		case totalRecv < netPrevRecv || totalSent < netPrevSent:
			// Counter decreased: reboot or interface reset. Reset baseline.
			cachedNetIn, cachedNetOut = -1, -1
		case netElapsed > 0:
			cachedNetIn = float64(totalRecv-netPrevRecv) / netElapsed
			cachedNetOut = float64(totalSent-netPrevSent) / netElapsed
		}
		netPrevRecv, netPrevSent, netPrevTime = totalRecv, totalSent, now
	}

	lastSampleTime = now

	return cachedCPU, append([]float64(nil), cachedPerCore...), cachedNetIn, cachedNetOut
}

// Collect gathers current system metrics
func Collect() Status {
	var s Status

	s.Uptime = uint64(time.Since(startTime).Seconds())

	s.CPU, s.CPUPerCore, s.NetInSpeed, s.NetOutSpeed = refreshDeltaMetrics()

	if loadAvg, err := load.Avg(); err == nil {
		s.Load1 = loadAvg.Load1
		s.Load5 = loadAvg.Load5
		s.Load15 = loadAvg.Load15
	}

	if vmStat, err := mem.VirtualMemory(); err == nil {
		s.MemTotal = vmStat.Total
		s.MemUsed = vmStat.Used
	}

	if swapStat, err := mem.SwapMemory(); err == nil {
		s.SwapTotal = swapStat.Total
		s.SwapUsed = swapStat.Used
	}

	if diskStat, err := disk.Usage("/"); err == nil {
		s.DiskTotal = diskStat.Total
		s.DiskUsed = diskStat.Used
	}

	// GC metrics
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.Goroutines = runtime.NumGoroutine()
	s.NumGC = ms.NumGC
	if ms.NumGC > 0 {
		// PauseNs is a ring buffer of the most recent GC pause times.
		idx := (ms.NumGC - 1) % uint32(len(ms.PauseNs))
		s.LastPauseMS = float64(ms.PauseNs[idx]) / 1e6
	}

	return s
}
