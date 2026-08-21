package monitor

import (
	"sync"
	"testing"

	"github.com/shirou/gopsutil/v4/cpu"
)

func TestCpuPercentDelta(t *testing.T) {
	prev := cpu.TimesStat{User: 100, System: 50, Idle: 850}  // total 1000, busy 150
	curr := cpu.TimesStat{User: 150, System: 75, Idle: 1275} // total 1500, busy 225

	// busy delta 75 over total delta 500 => 15%
	got := cpuPercentDelta(prev, curr, -1)
	if got != 15 {
		t.Fatalf("expected 15%%, got %v", got)
	}
}

func TestCpuPercentDeltaDegenerateWindowUsesFallback(t *testing.T) {
	// Two snapshots taken so close together that the jiffy counters haven't
	// advanced at all. gopsutil's own cpu.Percent would return a misleading
	// 100% here; ours must keep whatever the last known-good reading was.
	same := cpu.TimesStat{User: 100, System: 50, Idle: 850}

	got := cpuPercentDelta(same, same, 42)
	if got != 42 {
		t.Fatalf("expected fallback 42, got %v", got)
	}
}

func TestCpuPercentDeltaShrinkingTotalUsesFallback(t *testing.T) {
	// A counter going backwards (e.g. a stat source glitch) must not be
	// reported as a real reading; fall back rather than produce garbage.
	prev := cpu.TimesStat{User: 100, Idle: 900}
	curr := cpu.TimesStat{User: 100, Idle: 850}

	got := cpuPercentDelta(prev, curr, -1)
	if got != -1 {
		t.Fatalf("expected fallback -1 for shrinking total, got %v", got)
	}
}

func TestCpuPercentDeltaFullyBusyClampsTo100(t *testing.T) {
	prev := cpu.TimesStat{User: 0, Idle: 0}
	curr := cpu.TimesStat{User: 200, Idle: 0}

	got := cpuPercentDelta(prev, curr, -1)
	if got != 100 {
		t.Fatalf("expected 100%%, got %v", got)
	}
}

func TestRefreshDeltaMetricsCachesWithinMinInterval(t *testing.T) {
	// Reset package state so this test is independent of init()/other tests.
	sampleMu.Lock()
	hasSample = false
	sampleMu.Unlock()

	cpu1, perCore1, netIn1, netOut1 := refreshDeltaMetrics()
	cpu2, perCore2, netIn2, netOut2 := refreshDeltaMetrics()

	if cpu1 != cpu2 || netIn1 != netIn2 || netOut1 != netOut2 {
		t.Fatalf("expected identical cached values within min sample interval, got (%v,%v,%v) vs (%v,%v,%v)",
			cpu1, netIn1, netOut1, cpu2, netIn2, netOut2)
	}
	if len(perCore1) != len(perCore2) {
		t.Fatalf("expected identical per-core length, got %d vs %d", len(perCore1), len(perCore2))
	}
}

// TestCollectConcurrentNodesAgree simulates the exact scenario reported by
// users: several node goroutines on one machine (e.g. machine mode, or
// several nodes' push/WS tickers) calling Collect() at the same time. They
// must all observe the same CPU reading instead of each stealing a sliver of
// the others' sampling window.
func TestCollectConcurrentNodesAgree(t *testing.T) {
	sampleMu.Lock()
	hasSample = false
	sampleMu.Unlock()

	const nodes = 8
	results := make([]float64, nodes)

	var wg sync.WaitGroup
	wg.Add(nodes)
	for i := 0; i < nodes; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = Collect().CPU
		}(i)
	}
	wg.Wait()

	for i := 1; i < nodes; i++ {
		if results[i] != results[0] {
			t.Fatalf("node %d saw CPU=%v but node 0 saw CPU=%v within the same sampling window", i, results[i], results[0])
		}
	}
}
