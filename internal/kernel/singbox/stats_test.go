package singbox

import (
	"context"
	"errors"
	"testing"
)

func TestConnTrackerDialAndDeviceRejectStats(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetDeviceLimitFunc(func(string) (int, bool) { return 1, true })

	w := tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	for _, ip := range []string{"2.2.2.2", "3.3.3.3", "2.2.2.2"} {
		tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", ip), nil, nil)
	}

	tc, ok := w.(*trackedConn)
	if !ok {
		t.Fatalf("first connection not tracked: %T", w)
	}
	_ = tc.HandshakeFailure(errors.New("dial tcp 9.9.9.9:443: i/o timeout"))
	_ = tc.HandshakeFailure(errors.New("again")) // one connection = one failure

	total, fails := tracker.DialStats()
	if total != 1 || fails != 1 {
		t.Fatalf("DialStats() = %d, %d; want 1, 1 (refused connections are not dial attempts)", total, fails)
	}
	rej := tracker.DeviceRejects()
	r := rej[1]
	if r.Count != 3 || len(r.IPs) != 2 || r.IPs[0] != "3.3.3.3" || r.IPs[1] != "2.2.2.2" {
		t.Fatalf("DeviceRejects()[1] = %+v; want 3 refusals, IPs [3.3.3.3 2.2.2.2]", r)
	}
	r.IPs[0] = "x" // returned copy must not alias internal state
	if tracker.DeviceRejects()[1].IPs[0] != "3.3.3.3" {
		t.Fatal("DeviceRejects returned internal slice")
	}
}

func TestConnTrackerDeviceRejectIPsBounded(t *testing.T) {
	tracker := NewConnTracker(0)
	for i := 0; i < 50; i++ {
		tracker.noteDeviceReject(1, string(rune('a'+i%26))+"ip")
	}
	if r := tracker.DeviceRejects()[1]; r.Count != 50 || len(r.IPs) != deviceRejectIPs {
		t.Fatalf("got %d refusals, %d IPs", r.Count, len(r.IPs))
	}
}
