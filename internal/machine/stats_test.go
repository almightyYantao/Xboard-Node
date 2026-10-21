package machine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestStatsMachineView(t *testing.T) {
	o := New(&config.Config{
		Panel:   config.PanelConfig{URL: "https://panel.example.com/api/v2?token=secret"},
		Machine: &config.MachineConfig{MachineID: 7, Token: "t"},
	})
	o.setWanted([]panel.MachineNode{{ID: 2, Type: "trojan", Name: "b"}, {ID: 1, Type: "vless", Name: "a"}})
	o.nodes[1] = &nodeHandle{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the retry timer must not start anything
	h := &nodeHandle{}
	o.nodes[2] = h
	delay := o.nodeFailed(ctx, 2, h, time.Now(), errors.New("listen tcp :443: bind: address already in use"))
	o.statDiscovery.Fail(errors.New("timeout"))

	v := o.StatsMachineView()
	if v.ID != 7 || v.Panel != "panel.example.com" || v.WS != -1 || v.Discovery.Fails != 1 {
		t.Fatalf("view: %+v", v)
	}
	if len(v.Nodes) != 2 || v.Nodes[0].ID != 1 || !v.Nodes[0].Running || v.Nodes[0].Attempts != 0 {
		t.Fatalf("node 1: %+v", v.Nodes)
	}
	n := v.Nodes[1]
	if n.Running || n.Attempts != 1 || n.LastError == "" || n.LastExit == 0 || n.NextRetry < time.Now().Add(delay-time.Second).Unix() {
		t.Fatalf("node 2: %+v", n)
	}
}

func TestPanelHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://p.example.com:8443/x?token=1": "p.example.com:8443",
		"not a url":                            "",
		"":                                     "",
	} {
		if got := panelHost(in); got != want {
			t.Errorf("panelHost(%q) = %q, want %q", in, got, want)
		}
	}
}
