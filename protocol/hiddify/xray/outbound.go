package xray

import (
	"context"
	"encoding/json"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	xcore "github.com/xtls/xray-core/core"
	xconf "github.com/xtls/xray-core/infra/conf"
	xnet "github.com/xtls/xray-core/common/net"
	xcnc "github.com/xtls/xray-core/common/net/cnc"
	xsession "github.com/xtls/xray-core/common/session"
	xtransport "github.com/xtls/xray-core/transport"
	xpipe "github.com/xtls/xray-core/transport/pipe"
	xoutbound "github.com/xtls/xray-core/features/outbound"

	// Mandatory plumbing: Config.Build() always references these regardless of what the
	// wrapped outbound actually needs (dispatcher/proxyman are the App entries every
	// xray-core instance requires; app/log supplies the default log config).
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Protocols ray2sing's xray*.go link parsers (xrayvless.go/xrayvmess.go/xraytrojan.go/
	// xraydirect.go) can produce.
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"

	// Transports those protocols can be carried over.
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// xrayInternalOutboundTag is the fixed tag used inside the embedded, single-outbound xray-core
// instance. The manager/ray2sing-supplied tag (options.XConfig["tag"]) is discarded and replaced
// with this, since it's irrelevant beyond this package - sing-box's own tag (the outer Outbound.Tag)
// is what routing/UI actually see.
const xrayInternalOutboundTag = "out"

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.XrayOutboundOptions](registry, C.TypeXray, New)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger   logger.ContextLogger
	instance *xcore.Instance
	handler  xoutbound.Handler

	closeOnce sync.Once
}

// New builds a single-outbound, no-inbound xray-core instance from the raw xray-core outbound
// JSON carried in options.XConfig (protocol/settings/streamSettings, exactly the shape ray2sing's
// VlessXray/VmessXray/TrojanXray/DirectXray parsers, or a "Full Xray json" subscription's single
// outbound entry, produce), and dispatches sing-box Dial/ListenPacket calls straight to its
// outbound.Handler - bypassing xray-core's own routing/dispatcher entirely, since there is exactly
// one destination-less outbound and sing-box already decided to route here.
func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.XrayOutboundOptions) (adapter.Outbound, error) {
	if options.XConfig == nil {
		return nil, E.New("xray: missing xconfig")
	}

	rawOutbound, err := json.Marshal(*options.XConfig)
	if err != nil {
		return nil, E.Cause(err, "xray: marshal xconfig")
	}

	var outboundConf xconf.OutboundDetourConfig
	if err := json.Unmarshal(rawOutbound, &outboundConf); err != nil {
		return nil, E.Cause(err, "xray: parse xconfig")
	}
	outboundConf.Tag = xrayInternalOutboundTag

	coreConfig, err := (&xconf.Config{
		OutboundConfigs: []xconf.OutboundDetourConfig{outboundConf},
	}).Build()
	if err != nil {
		return nil, E.Cause(err, "xray: build config")
	}

	instance, err := xcore.New(coreConfig)
	if err != nil {
		return nil, E.Cause(err, "xray: create instance")
	}
	if err := instance.Start(); err != nil {
		return nil, E.Cause(err, "xray: start instance")
	}

	manager, ok := instance.GetFeature(xoutbound.ManagerType()).(xoutbound.Manager)
	if !ok {
		instance.Close()
		return nil, E.New("xray: outbound manager unavailable")
	}
	handler := manager.GetHandler(xrayInternalOutboundTag)
	if handler == nil {
		instance.Close()
		return nil, E.New("xray: outbound handler not registered")
	}

	return &Outbound{
		Adapter:  outbound.NewAdapter(C.TypeXray, tag, []string{"tcp", "udp"}, nil),
		logger:   logger,
		instance: instance,
		handler:  handler,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dest := socksaddrToXrayDestination(destination, network == "udp")
	link, conn := newBridgedConn(dest)
	h.logger.InfoContext(ctx, "xray outbound connection to ", destination)
	go h.handler.Dispatch(withXrayOutboundTarget(ctx, dest), link)
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dest := socksaddrToXrayDestination(destination, true)
	link, conn := newBridgedConn(dest)
	h.logger.InfoContext(ctx, "xray outbound packet connection to ", destination)
	go h.handler.Dispatch(withXrayOutboundTarget(ctx, dest), link)
	return &packetConn{Conn: conn, remote: destination}, nil
}

func (h *Outbound) Close() error {
	var err error
	h.closeOnce.Do(func() {
		if h.instance != nil {
			err = h.instance.Close()
		}
	})
	return err
}

func withXrayOutboundTarget(ctx context.Context, dest xnet.Destination) context.Context {
	return xsession.ContextWithOutbounds(ctx, []*xsession.Outbound{{Target: dest}})
}

func socksaddrToXrayDestination(destination M.Socksaddr, udp bool) xnet.Destination {
	var addr xnet.Address
	if destination.IsFqdn() {
		addr = xnet.DomainAddress(destination.Fqdn)
	} else {
		addr = xnet.IPAddress(destination.Addr.AsSlice())
	}
	port := xnet.Port(destination.Port)
	if udp {
		return xnet.UDPDestination(addr, port)
	}
	return xnet.TCPDestination(addr, port)
}

// newBridgedConn wires up a pair of xray-core pipes into a transport.Link (handed to the outbound
// handler) and a net.Conn (handed back to sing-box), so writes on the net.Conn become reads on the
// handler's link.Reader, and the handler's link.Writer becomes reads on the net.Conn - the same
// buf.Reader/buf.Writer <-> net.Conn bridge xray-core's own proxy/loopback outbound uses to hand a
// dispatched connection back out as a plain net.Conn.
func newBridgedConn(dest xnet.Destination) (*xtransport.Link, net.Conn) {
	uplinkReader, uplinkWriter := xpipe.New()
	downlinkReader, downlinkWriter := xpipe.New()

	link := &xtransport.Link{Reader: uplinkReader, Writer: downlinkWriter}

	var outputOpt xcnc.ConnectionOption
	if dest.Network == xnet.Network_UDP {
		outputOpt = xcnc.ConnectionOutputMultiUDP(downlinkReader)
	} else {
		outputOpt = xcnc.ConnectionOutputMulti(downlinkReader)
	}
	conn := xcnc.NewConnection(xcnc.ConnectionInputMulti(uplinkWriter), outputOpt)
	return link, conn
}

// packetConn adapts the connected, single-destination net.Conn newBridgedConn returns into a
// net.PacketConn - outbound UDP-through-a-proxy-tag is inherently tied to one destination for the
// life of the dispatch, so ReadFrom/WriteTo just report/ignore that fixed peer address.
type packetConn struct {
	net.Conn
	remote M.Socksaddr
}

func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(p)
	return n, c.remote.UDPAddr(), err
}

func (c *packetConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.Conn.Write(p)
}
