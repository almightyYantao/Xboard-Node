package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// flakySource fails Poll while fail is set. Other methods are not used here.
type flakySource struct {
	controlplane.ControlPlane
	fail atomic.Bool
}

func (f *flakySource) SupportsPolling() bool { return true }
func (f *flakySource) Poll(context.Context) (controlplane.Snapshot, error) {
	if f.fail.Load() {
		return controlplane.Snapshot{}, errors.New(`Get "https://panel/api": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`)
	}
	return controlplane.Snapshot{}, nil
}

// pullOnce runs one poll and waits for it, ignoring the backoff skip.
func pullOnce(t *testing.T, s *Service) {
	t.Helper()
	s.pullBackoff.onSuccess() // the test drives every attempt
	s.pullViaAPIAsync(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for s.pullActive.Load() {
		if time.Now().After(deadline) {
			t.Fatal("poll did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-s.pullResults:
	default:
	}
}

func TestPollFailuresLogOnceAndRecovery(t *testing.T) {
	var buf bytes.Buffer
	nlog.Init(&buf, slog.LevelInfo, false)
	defer nlog.Init(nil, slog.LevelInfo, false)

	src := &flakySource{}
	s := newTestService(&fakeKernel{})
	s.source, s.pullResults = src, make(chan pullResult, 1)
	s.pullLog = nlog.Streak{Name: "poll control plane"}

	src.fail.Store(true)
	for i := 0; i < 6; i++ {
		pullOnce(t, s)
	}
	out := buf.String()
	if n := strings.Count(out, "poll control plane failed"); n != 1 {
		t.Fatalf("want 1 failure line for 6 failures, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "Client.Timeout") || !strings.Contains(out, "WARN") {
		t.Fatalf("failure line should keep the cause at WARN:\n%s", out)
	}
	if got := s.statPull.Snapshot().Fails; got != 6 {
		t.Fatalf("stats must still count every failure (watchdog reads them): %d", got)
	}

	buf.Reset()
	src.fail.Store(false)
	pullOnce(t, s)
	pullOnce(t, s)
	out = buf.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "poll control plane recovered") || !strings.Contains(out, "failures=6") {
		t.Fatalf("want exactly one recovery line:\n%s", out)
	}
	if s.statPull.Snapshot().Fails != 0 {
		t.Fatal("stats not reset on success")
	}
}

func TestReportPushedIsDebug(t *testing.T) {
	var buf bytes.Buffer
	nlog.Init(&buf, slog.LevelInfo, false)
	defer nlog.Init(nil, slog.LevelInfo, false)
	for i := 0; i < 10; i++ {
		nlog.ReportPushed(3, 1)
	}
	if buf.Len() != 0 {
		t.Fatalf("periodic success logged at INFO:\n%s", buf.String())
	}
}
