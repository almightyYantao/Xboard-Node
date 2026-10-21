package singbox

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
)

// captureManager records the metadata the outbound hands to the connection
// manager — the addresses it would dial.
type captureManager struct {
	adapter.ConnectionManager
	got []netip.Addr
}

func (m *captureManager) NewConnection(_ context.Context, _ N.Dialer, _ net.Conn, md adapter.InboundContext, _ N.CloseHandlerFunc) {
	m.got = md.DestinationAddresses
}

func (m *captureManager) NewPacketConnection(_ context.Context, _ N.Dialer, _ N.PacketConn, md adapter.InboundContext, _ N.CloseHandlerFunc) {
	m.got = md.DestinationAddresses
}

// The constraint has to survive the hop from tracker to outbound; this is the
// half that is invisible in config and easy to lose in a refactor.
func TestACLDirectOutboundNarrowsDialAddresses(t *testing.T) {
	internal := netip.MustParseAddr("10.101.30.4")
	public := netip.MustParseAddr("183.129.228.249")
	md := adapter.InboundContext{DestinationAddresses: []netip.Addr{internal, public}}

	for _, tc := range []struct {
		name string
		conn net.Conn
		want []netip.Addr
	}{
		{"constrained", &trackedConn{dialOnly: []netip.Addr{public}}, []netip.Addr{public}},
		{"unconstrained tracked", &trackedConn{}, []netip.Addr{internal, public}},
		{"untracked", nil, []netip.Addr{internal, public}},
	} {
		m := &captureManager{}
		o := &aclDirectOutbound{connection: m}
		o.NewConnectionEx(context.Background(), tc.conn, md, nil)
		if !slices.Equal(m.got, tc.want) {
			t.Errorf("tcp %s: dialed %v, want %v", tc.name, m.got, tc.want)
		}
	}

	m := &captureManager{}
	o := &aclDirectOutbound{connection: m}
	o.NewPacketConnectionEx(context.Background(), &trackedPacketConn{dialOnly: []netip.Addr{public}}, md, nil)
	if !slices.Equal(m.got, []netip.Addr{public}) {
		t.Errorf("udp constrained: dialed %v, want [%v]", m.got, public)
	}
}

// boxContext must actually replace the stock direct outbound, or the
// constraint is computed and then ignored.
func TestBoxContextRegistersACLDirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = boxContext(ctx)
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx,
		[]byte(`{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}]}`))
	if err != nil {
		t.Fatalf("parse options: %v", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	defer instance.Close()
	out, ok := instance.Outbound().Outbound("direct")
	if !ok {
		t.Fatal("direct outbound missing")
	}
	if _, ok := out.(*aclDirectOutbound); !ok {
		t.Errorf("direct outbound is %T, want *aclDirectOutbound", out)
	}
}
