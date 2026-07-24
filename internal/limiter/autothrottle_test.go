package limiter

import (
	"testing"
	"time"
)

func params() AutoThrottleParams {
	return AutoThrottleParams{
		ThresholdBps:    1_000_000, // 8 Mbps
		TriggerCycles:   2,
		PenaltyBps:      100_000,
		KickAfterCycles: 2,
		Release:         30 * time.Second,
	}
}

func TestAutoThrottleTriggersThenKicksThenReleases(t *testing.T) {
	a := NewAutoThrottle()
	p := params()
	t0 := time.Unix(1_700_000_000, 0)
	hot := map[int]int64{1: 2_000_000} // over threshold
	cold := map[int]int64{1: 10}       // under threshold

	// Cycle 1: hot but below TriggerCycles → no action yet.
	d := a.Evaluate(t0, p, hot)
	if len(d.Throttle) != 0 || len(d.Kick) != 0 {
		t.Fatalf("cycle1: expected no action, got %+v", d)
	}

	// Cycle 2: reaches TriggerCycles → throttle.
	d = a.Evaluate(t0.Add(10*time.Second), p, hot)
	if d.Throttle[1] != p.PenaltyBps {
		t.Fatalf("cycle2: expected throttle to %d, got %+v", p.PenaltyBps, d)
	}
	if len(d.Kick) != 0 {
		t.Fatalf("cycle2: unexpected kick %+v", d.Kick)
	}

	// Cycles 3-4: still hot while throttled → after KickAfterCycles, kick.
	a.Evaluate(t0.Add(20*time.Second), p, hot) // throttledHot=1
	d = a.Evaluate(t0.Add(30*time.Second), p, hot)
	if len(d.Kick) != 1 || d.Kick[0] != 1 {
		t.Fatalf("expected kick of user 1, got %+v", d.Kick)
	}
	// Still throttled every hot cycle.
	if d.Throttle[1] != p.PenaltyBps {
		t.Fatalf("expected sustained throttle, got %+v", d.Throttle)
	}

	// Goes cold but within cooldown → stays throttled, not released.
	d = a.Evaluate(t0.Add(40*time.Second), p, cold)
	if len(d.Clear) != 0 {
		t.Fatalf("expected no release within cooldown, got %+v", d.Clear)
	}

	// After cooldown elapses while cold → release.
	d = a.Evaluate(t0.Add(200*time.Second), p, cold)
	if len(d.Clear) != 1 || d.Clear[0] != 1 {
		t.Fatalf("expected release of user 1, got %+v", d.Clear)
	}
	if a.Active() {
		t.Fatal("expected engine idle after release")
	}
}

func TestAutoThrottleDisabledReleasesAll(t *testing.T) {
	a := NewAutoThrottle()
	p := params()
	t0 := time.Unix(1_700_000_000, 0)
	hot := map[int]int64{7: 5_000_000}

	a.Evaluate(t0, p, hot)
	a.Evaluate(t0.Add(10*time.Second), p, hot) // throttled now

	// Policy disabled → releases everyone, forgets state.
	d := a.Evaluate(t0.Add(20*time.Second), AutoThrottleParams{}, hot)
	if len(d.Clear) != 1 || d.Clear[0] != 7 {
		t.Fatalf("expected release of user 7 on disable, got %+v", d.Clear)
	}
	if a.Active() {
		t.Fatal("expected no tracked state after disable")
	}
}
