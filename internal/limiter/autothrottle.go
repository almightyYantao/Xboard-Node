package limiter

import (
	"sync"
	"time"
)

// AutoThrottleParams is the resolved (bytes/sec, absolute-duration) form of the
// panel's auto-mitigation policy. The service converts the Mbps/seconds config
// into this before each evaluation. A non-positive ThresholdBps or TriggerCycles
// means the feature is disabled.
type AutoThrottleParams struct {
	ThresholdBps    int64         // total (up+down) bytes/sec above which a user is "hot"
	TriggerCycles   int           // consecutive hot cycles before throttling kicks in
	PenaltyBps      int           // throttle-to rate once triggered
	KickAfterCycles int           // hot cycles while throttled before a (repeat) kick; 0 = never kick
	Release         time.Duration // penalty lifts after this long continuously below threshold
}

func (p AutoThrottleParams) enabled() bool {
	return p.ThresholdBps > 0 && p.TriggerCycles > 0
}

// autoState is the per-user penalty-box state machine.
type autoState struct {
	hotStreak    int       // consecutive hot cycles before throttling
	throttled    bool      // penalty rate currently applied
	throttledHot int       // consecutive hot cycles since throttling (drives re-kick)
	until        time.Time // penalty expiry; extended on every hot cycle
}

// AutoThrottle tracks per-user throughput over successive track cycles and
// decides when to throttle, (re-)kick, or release a user. It holds no timers or
// I/O of its own — Evaluate returns a decision the caller applies. Thread-safe.
type AutoThrottle struct {
	mu    sync.Mutex
	state map[int]*autoState
}

// NewAutoThrottle creates an empty engine.
func NewAutoThrottle() *AutoThrottle {
	return &AutoThrottle{state: make(map[int]*autoState)}
}

// Active reports whether any user is currently tracked (hot streak or penalty),
// so the caller can skip work when the feature is idle and disabled.
func (a *AutoThrottle) Active() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.state) > 0
}

// ThrottleDecision is the set of actions to apply after one Evaluate call.
type ThrottleDecision struct {
	Throttle map[int]int // userID → penalty bytes/sec to (re)apply this cycle
	Clear    []int       // userIDs whose penalty should be lifted
	Kick     []int       // userIDs to force-close now
}

// Evaluate advances the state machine by one track cycle. speeds maps userID →
// current total throughput in bytes/sec. When the policy is disabled it releases
// everyone and forgets all state.
func (a *AutoThrottle) Evaluate(now time.Time, p AutoThrottleParams, speeds map[int]int64) ThrottleDecision {
	a.mu.Lock()
	defer a.mu.Unlock()

	var d ThrottleDecision

	if !p.enabled() {
		for uid := range a.state {
			d.Clear = append(d.Clear, uid)
		}
		a.state = make(map[int]*autoState)
		return d
	}

	// Evaluate every currently-hot user (creating state on first sight) plus
	// every already-tracked user (as not-hot if absent from this cycle).
	seen := make(map[int]bool, len(speeds))
	for uid, bps := range speeds {
		seen[uid] = true
		hot := bps > p.ThresholdBps
		st := a.state[uid]
		if st == nil {
			if !hot {
				continue
			}
			st = &autoState{}
			a.state[uid] = st
		}
		a.step(now, p, uid, st, hot, &d)
	}
	for uid, st := range a.state {
		if seen[uid] {
			continue
		}
		a.step(now, p, uid, st, false, &d)
	}
	return d
}

// step advances a single user's state for this cycle.
func (a *AutoThrottle) step(now time.Time, p AutoThrottleParams, uid int, st *autoState, hot bool, d *ThrottleDecision) {
	if hot {
		st.until = now.Add(p.Release)
		if !st.throttled {
			st.hotStreak++
			if st.hotStreak >= p.TriggerCycles {
				st.throttled = true
				st.throttledHot = 0
			}
		} else {
			st.throttledHot++
			if p.KickAfterCycles > 0 && st.throttledHot >= p.KickAfterCycles {
				st.throttledHot = 0 // re-arm: kick again only after another run of hot cycles
				d.Kick = append(d.Kick, uid)
			}
		}
	} else {
		st.hotStreak = 0
		if st.throttled && !now.Before(st.until) {
			d.Clear = append(d.Clear, uid)
			delete(a.state, uid)
			return
		}
	}

	if st.throttled {
		if d.Throttle == nil {
			d.Throttle = make(map[int]int)
		}
		d.Throttle[uid] = p.PenaltyBps
	}
}
