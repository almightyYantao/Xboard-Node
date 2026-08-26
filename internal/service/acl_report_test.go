package service

import (
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

// fakeAccessSink captures what pushAccessLogAsync would send to the panel.
type fakeAccessSink struct {
	mu      sync.Mutex
	records []map[string]any
	agent   map[string]any
	called  bool
}

func (f *fakeAccessSink) PushAccessLog(records []map[string]any, agent map[string]any) (*bool, string, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = records
	f.agent = agent
	f.called = true
	return nil, "", nil, nil
}

// The rest of controlplane.Sink is unused by pushAccessLogAsync, which only
// type-asserts to accessLogPusher.
func (f *fakeAccessSink) Report(controlplane.ReportPayload) error                 { return nil }
func (f *fakeAccessSink) ReportDevices(controlplane.PushClient, map[int][]string) {}
func (f *fakeAccessSink) SupportsReporting() bool                                 { return true }
func (f *fakeAccessSink) SupportsDeviceReports() bool                             { return false }

func (f *fakeAccessSink) wait(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		done := f.called
		f.mu.Unlock()
		if done {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("PushAccessLog was never called")
}

func newReportService(k *fakeKernel, sink *fakeAccessSink) *Service {
	s := newTestService(k)
	s.sink = sink
	s.tracker = tracker.New()
	return s
}

// An ACL verdict must reach the panel with its mode, action, and matched
// rule, so the dry-run view can aggregate by user / group / rule.
func TestPushAccessLogCarriesACLFields(t *testing.T) {
	k := &fakeKernel{running: true, aclDenials: 7}
	k.accessRecords = []model.AccessRecord{{
		Time:      1700000000000,
		UserID:    42,
		SourceIP:  "203.0.113.9",
		DestHost:  "10.9.0.5",
		DestPort:  443,
		Network:   "tcp",
		ACLMode:   "dryrun",
		ACLAction: "deny",
		ACLRule:   "vip#1",
	}}
	sink := &fakeAccessSink{}
	s := newReportService(k, sink)

	s.pushAccessLogAsync()
	sink.wait(t)

	if len(sink.records) != 1 {
		t.Fatalf("records = %d, want 1", len(sink.records))
	}
	r := sink.records[0]
	for key, want := range map[string]any{
		"user_id":    42,
		"dest_host":  "10.9.0.5",
		"dest_port":  443,
		"network":    "tcp",
		"acl_mode":   "dryrun",
		"acl_action": "deny",
		"acl_rule":   "vip#1",
	} {
		if got := r[key]; got != want {
			t.Errorf("record[%q] = %v, want %v", key, got, want)
		}
	}

	// ACL records are emitted at connection start, so they carry no traffic.
	for _, key := range []string{"upload_bytes", "download_bytes", "duration_ms"} {
		if got := r[key]; got != int64(0) {
			t.Errorf("record[%q] = %v, want 0", key, got)
		}
	}
}

// A plain access record must not grow ACL keys — the panel distinguishes the
// two kinds by their presence.
func TestPushAccessLogOmitsACLFieldsOnPlainRecords(t *testing.T) {
	k := &fakeKernel{running: true}
	k.accessRecords = []model.AccessRecord{{
		Time: 1700000000000, UserID: 7, DestHost: "example.com",
		DestPort: 443, Network: "tcp", Upload: 100, Download: 200, DurationMs: 50,
	}}
	sink := &fakeAccessSink{}
	s := newReportService(k, sink)

	s.pushAccessLogAsync()
	sink.wait(t)

	r := sink.records[0]
	for _, key := range []string{"acl_mode", "acl_action", "acl_rule"} {
		if _, present := r[key]; present {
			t.Errorf("plain record must not carry %q", key)
		}
	}
}

// The exact denial counter travels with every push, including the idle ones
// that carry no records — a full buffer must cost detail, never accuracy.
func TestPushAccessLogReportsExactDenialTotals(t *testing.T) {
	k := &fakeKernel{running: true, aclDenials: 12345}
	sink := &fakeAccessSink{}
	s := newReportService(k, sink)

	s.pushAccessLogAsync()
	sink.wait(t)

	if len(sink.records) != 0 {
		t.Errorf("records = %d, want 0", len(sink.records))
	}
	if got := sink.agent["acl_denials"]; got != uint64(12345) {
		t.Errorf("agent[acl_denials] = %v, want 12345", got)
	}
	if got := sink.agent["acl_records"]; got != 0 {
		t.Errorf("agent[acl_records] = %v, want 0", got)
	}
	if got := sink.agent["acl_mode"]; got != "off" {
		t.Errorf("agent[acl_mode] = %v, want off", got)
	}
}

// acl_records counts only the ACL subset, so the panel can tell how much of
// the exact total it actually received samples for.
func TestPushAccessLogCountsOnlyACLRecords(t *testing.T) {
	k := &fakeKernel{running: true, aclDenials: 3}
	k.accessRecords = []model.AccessRecord{
		{Time: 1, UserID: 1, DestHost: "a.com", ACLAction: "deny", ACLMode: "enforce", ACLRule: "g#0"},
		{Time: 2, UserID: 2, DestHost: "b.com", Upload: 10},
		{Time: 3, UserID: 3, DestHost: "c.com", ACLAction: "deny", ACLMode: "enforce", ACLRule: "g#1"},
	}
	sink := &fakeAccessSink{}
	s := newReportService(k, sink)

	s.pushAccessLogAsync()
	sink.wait(t)

	if len(sink.records) != 3 {
		t.Fatalf("records = %d, want 3", len(sink.records))
	}
	if got := sink.agent["acl_records"]; got != 2 {
		t.Errorf("agent[acl_records] = %v, want 2", got)
	}
	if got := sink.agent["acl_denials"]; got != uint64(3) {
		t.Errorf("agent[acl_denials] = %v, want 3", got)
	}
}

func TestAccessRecordIsACL(t *testing.T) {
	if (model.AccessRecord{}).IsACL() {
		t.Error("plain record must not report as ACL")
	}
	if !(model.AccessRecord{ACLAction: "deny"}).IsACL() {
		t.Error("record with acl_action must report as ACL")
	}
}
