package singbox

import (
	"context"
	"net"
	"net/netip"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// aclDirectOutbound is sing-box's direct outbound plus one thing: it honours
// the ACL's dial constraint.
//
// The ACL judges a resolved name per address and allows it when any address
// is allowed, so the kernel must dial the allowed addresses and nothing else —
// failing over to a denied address in the same DNS answer would open what the
// ACL guards. Allowed internal addresses also go first (acl.preferInternal). The ACL decides in ConnTracker, but the router
// passes trackers a copy of the metadata, so the tracker cannot narrow
// DestinationAddresses itself. It records the constraint on the conn it
// wraps instead, and this outbound — which receives that wrapped conn —
// narrows the addresses before dialing.
//
// Everything else is the embedded *direct.Outbound, so every interface the
// rest of sing-box type-asserts on it (parallel dialing, direct-route, ...)
// still holds. A conn without a constraint takes the same path the router
// would have taken itself: ConnectionManager.NewConnection.
type aclDirectOutbound struct {
	*direct.Outbound
	connection adapter.ConnectionManager
}

var (
	_ adapter.ConnectionHandlerEx       = (*aclDirectOutbound)(nil)
	_ adapter.PacketConnectionHandlerEx = (*aclDirectOutbound)(nil)
)

func newACLDirectOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (adapter.Outbound, error) {
	inner, err := direct.NewOutbound(ctx, router, logger, tag, options)
	if err != nil {
		return nil, err
	}
	d, ok := inner.(*direct.Outbound)
	if !ok {
		return nil, E.New("unexpected direct outbound type ", inner.Type())
	}
	connection := service.FromContext[adapter.ConnectionManager](ctx)
	if connection == nil {
		return nil, E.New("connection manager not registered")
	}
	return &aclDirectOutbound{Outbound: d, connection: connection}, nil
}

func (o *aclDirectOutbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if tc, ok := conn.(*trackedConn); ok {
		metadata.DestinationAddresses = narrowAddresses(metadata.DestinationAddresses, tc.dialOnly)
	}
	o.connection.NewConnection(ctx, o, conn, metadata, onClose)
}

func (o *aclDirectOutbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if tc, ok := conn.(*trackedPacketConn); ok {
		metadata.DestinationAddresses = narrowAddresses(metadata.DestinationAddresses, tc.dialOnly)
	}
	o.connection.NewPacketConnection(ctx, o, conn, metadata, onClose)
}

// narrowAddresses applies a dial constraint. nil means no constraint.
func narrowAddresses(addrs, dialOnly []netip.Addr) []netip.Addr {
	if dialOnly == nil {
		return addrs
	}
	return dialOnly
}

// boxContext is include.Context with the direct outbound swapped for
// aclDirectOutbound. Registering under the same type name replaces the
// stock constructor, so configs keep saying "type": "direct".
func boxContext(ctx context.Context) context.Context {
	outbounds := include.OutboundRegistry()
	outbound.Register[option.DirectOutboundOptions](outbounds, C.TypeDirect, newACLDirectOutbound)
	return box.Context(ctx, include.InboundRegistry(), outbounds, include.EndpointRegistry(),
		include.DNSTransportRegistry(), include.ServiceRegistry())
}
