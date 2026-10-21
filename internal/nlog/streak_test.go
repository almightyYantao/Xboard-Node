package nlog

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func capture(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	Init(&buf, level, false)
	t.Cleanup(func() { Init(nil, slog.LevelInfo, false) })
	return &buf
}

func lines(b *bytes.Buffer) []string {
	s := strings.TrimSpace(b.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestStreakQuietWhileFailing(t *testing.T) {
	buf := capture(t, slog.LevelInfo)
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s := &Streak{Name: "poll control plane", now: c.now}
	err := errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")

	// 30 failures one per 30 s = 15 minutes.
	for i := 0; i < 30; i++ {
		s.Fail(err)
		c.t = c.t.Add(30 * time.Second)
	}
	l := lines(buf)
	if len(l) != 2 {
		t.Fatalf("want first failure + one 10-min summary, got %d lines:\n%s", len(l), buf)
	}
	if !strings.Contains(l[0], "WARN") || !strings.Contains(l[0], "poll control plane failed") || !strings.Contains(l[0], "Client.Timeout") {
		t.Errorf("first line: %s", l[0])
	}
	if !strings.Contains(l[1], "poll control plane still failing") || !strings.Contains(l[1], "failures=21") || !strings.Contains(l[1], "for=10m0s") {
		t.Errorf("summary line: %s", l[1])
	}
	if s.Failing() != 30 {
		t.Errorf("Failing() = %d", s.Failing())
	}

	buf.Reset()
	if !s.OK() {
		t.Fatal("OK after failures should report recovery")
	}
	l = lines(buf)
	if len(l) != 1 || !strings.Contains(l[0], "INFO") || !strings.Contains(l[0], "poll control plane recovered") ||
		!strings.Contains(l[0], "failures=30") || !strings.Contains(l[0], "after=15m0s") {
		t.Fatalf("recovery: %v", l)
	}

	buf.Reset()
	for i := 0; i < 100; i++ {
		if s.OK() {
			t.Fatal("plain success must not log")
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("successes logged: %s", buf)
	}

	// A new streak starts over with a WARN.
	s.Fail(err)
	if l := lines(buf); len(l) != 1 || !strings.Contains(l[0], "poll control plane failed") {
		t.Fatalf("new streak: %v", l)
	}
}

func TestStreakDebugShowsEveryFailure(t *testing.T) {
	buf := capture(t, slog.LevelDebug)
	s := &Streak{Name: "push report"}
	for i := 0; i < 5; i++ {
		s.Fail(errors.New("x"))
	}
	if l := lines(buf); len(l) != 5 || !strings.Contains(l[4], "failures=5") {
		t.Fatalf("debug level should show each failure: %v", l)
	}
}

func TestStreakConcurrent(t *testing.T) {
	capture(t, slog.LevelError)
	s := &Streak{Name: "x"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if j%10 == 0 {
					s.OK()
				} else {
					s.Fail(errors.New("e"))
				}
			}
		}()
	}
	wg.Wait()
}
