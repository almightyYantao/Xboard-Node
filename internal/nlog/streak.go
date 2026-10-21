package nlog

import (
	"sync"
	"time"
)

// DefaultStreakSummary is how often a still-failing operation is summarized.
const DefaultStreakSummary = 10 * time.Minute

// Streak keeps a recurring operation (panel poll, report push, ws reconnect …)
// from filling small device logs while still reporting every state change:
//
//   - first failure:            WARN  "<name> failed"            error=…
//   - further failures:         DEBUG, plus at most one WARN "<name> still failing"
//     (failures=…, for=…) per Every
//   - first success afterwards: INFO  "<name> recovered"         failures=… after=…
//   - other successes:          nothing (callers may log them at DEBUG)
//
// Safe for concurrent use; the zero value needs only Name.
type Streak struct {
	Name  string
	Every time.Duration // summary interval; 0 = DefaultStreakSummary
	Log   *NodeLog      // nil = Core()

	mu      sync.Mutex
	fails   int
	first   time.Time
	lastLog time.Time
	now     func() time.Time // tests
}

func (s *Streak) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Streak) logger() *NodeLog {
	if s.Log != nil {
		return s.Log
	}
	return Core()
}

// Fail records a failure. args are extra key/value pairs for the log line.
func (s *Streak) Fail(err error, args ...any) {
	s.mu.Lock()
	now := s.clock()
	s.fails++
	n, first := s.fails, s.fails == 1
	every := s.Every
	if every <= 0 {
		every = DefaultStreakSummary
	}
	summary := !first && now.Sub(s.lastLog) >= every
	if first {
		s.first = now
	}
	if first || summary {
		s.lastLog = now
	}
	since := now.Sub(s.first).Round(time.Second)
	s.mu.Unlock()

	kv := append([]any{"error", err}, args...)
	switch {
	case first:
		s.logger().Warn(s.Name+" failed", kv...)
	case summary:
		s.logger().Warn(s.Name+" still failing", append([]any{"failures", n, "for", since.String()}, kv...)...)
	default:
		s.logger().Debug(s.Name+" failed", append([]any{"failures", n}, kv...)...)
	}
}

// OK records a success. It logs (and returns true) only when it ends a
// failure streak.
func (s *Streak) OK() bool {
	s.mu.Lock()
	if s.fails == 0 {
		s.mu.Unlock()
		return false
	}
	n, after := s.fails, s.clock().Sub(s.first).Round(time.Second)
	s.fails = 0
	s.mu.Unlock()
	s.logger().Info(s.Name+" recovered", "failures", n, "after", after.String())
	return true
}

// Failing reports the current number of consecutive failures.
func (s *Streak) Failing() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fails
}
