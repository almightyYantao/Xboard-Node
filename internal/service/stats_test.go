package service

import (
	"errors"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

func TestStatsView(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.cfg = &config.Config{Panel: config.PanelConfig{NodeID: 5}, Node: config.NodeConfig{TrackInterval: 10}, Kernel: config.KernelConfig{Type: "singbox"}}
	s.tracker = tracker.New()
	s.tracker.EnableTotals()
	s.tracker.Process(map[int][2]int64{1: {100, 200}}, map[int]map[string]bool{1: {"1.1.1.1": true}}, 2)
	s.lastConfig = &model.NodeSpec{Protocol: "vless", ServerPort: 8443}
	s.lastUsers = []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 2}, {ID: 2, UUID: "uuid-2"}}
	s.accessLogOn.Store(true)
	s.statPull.Fail(errors.New("Client.Timeout exceeded"))
	s.statPush.OK()

	v := s.StatsView()
	if v.ID != 5 || v.Protocol != "vless" || v.Port != 8443 || v.Kernel != "singbox" || !v.Running || v.TrackInterval != 10 {
		t.Fatalf("basic fields: %+v", v)
	}
	if len(v.Users) != 2 || v.Users[1].DeviceLimit != 2 || v.Users[1].UUID != "uuid-1" {
		t.Fatalf("users: %+v", v.Users)
	}
	if v.Tracker.Totals[1] != [2]int64{100, 200} || v.Tracker.ConnCount != 2 {
		t.Fatalf("tracker: %+v", v.Tracker)
	}
	if !v.AccessLog || v.Pull.Fails != 1 || v.Push.LastOK == 0 || v.WS != -1 {
		t.Fatalf("state: %+v", v)
	}
	if v.DialSupported || v.UserConns != nil || v.Rejects != nil {
		t.Fatalf("fake kernel has no optional capabilities: %+v", v)
	}
}
