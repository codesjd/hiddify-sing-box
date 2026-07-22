package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	xnet "github.com/xtls/xray-core/common/net"
	xcnc "github.com/xtls/xray-core/common/net/cnc"
	xsession "github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"
	xoutbound "github.com/xtls/xray-core/features/outbound"
	xconf "github.com/xtls/xray-core/infra/conf"
	xtransport "github.com/xtls/xray-core/transport"
	xpipe "github.com/xtls/xray-core/transport/pipe"

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

// normalizeRangeObjects rewrites every {"from": N, "to": M} object anywhere in a decoded JSON
// tree into the "N-M" string form (or a plain "N" when N == M) that xray-core's own JSON schema
// actually accepts for its Int32Range-typed fields (xhttp's xPaddingBytes/scMaxEachPostBytes/
// scMinPostsIntervalMs/scStreamUpServerSecs, xmux's maxConcurrency/maxConnections/cMaxReuseTimes/
// hMaxRequestTimes/hMaxReusableSecs, etc). xray-core's infra/conf.Int32Range.UnmarshalJSON only
// understands a plain integer or a "1-2" string; some panels (including hiddify-manager) instead
// emit the range as an object, which fails with "Invalid integer range..." if handed to xray-core
// unmodified. No field in xray-core's schema legitimately uses literal "from"/"to" keys for
// anything else, so this transform is unambiguous wherever it fires - including inside nested
// "extra"/"downloadSettings" blocks, which is why it walks the whole tree rather than only the
// known field names.
func normalizeRangeObjects(v any) any {
	switch val := v.(type) {
	case map[string]any:
		if len(val) == 2 {
			from, hasFrom := val["from"]
			to, hasTo := val["to"]
			if hasFrom && hasTo {
				if fromNum, ok := from.(float64); ok {
					if toNum, ok := to.(float64); ok {
						if fromNum == toNum {
							return strconv.FormatInt(int64(fromNum), 10)
						}
						return fmt.Sprintf("%d-%d", int64(fromNum), int64(toNum))
					}
				}
			}
		}
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[k] = normalizeRangeObjects(item)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = normalizeRangeObjects(item)
		}
		return out
	default:
		return v
	}
}

// clampKcpMtu rewrites any "mtu" key found anywhere in the raw JSON tree whose value falls outside
// xray-core's own hard-enforced KCP MTU range into the nearest boundary value, logging what it did.
// infra/conf.KCPConfig.Build() rejects anything outside 576-1460 with a build error rather than a
// warning (verified against both the exact xray-core version this project vendors and the current
// github.com/hiddify/xray-core source), and "mtu" appears exactly once in xray-core's entire
// outbound JSON schema - on KCPConfig - so this is unambiguous wherever it fires. hiddify-manager's
// own generated subscriptions intentionally use small MTUs (observed: 132) for xdns/xicmp entries,
// whose payloads are tiny DNS-sized UDP packets - a reasonable choice at the KCP-protocol level,
// just one this embedded engine's config-time validation refuses outright instead of merely
// flagging. Clamping to the nearest value the engine will actually accept lets the outbound build
// and run - KCP just uses slightly larger frames than strictly necessary - instead of failing to
// start at all.
func clampKcpMtu(ctx context.Context, logger logger.ContextLogger, v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			if k == "mtu" {
				if num, ok := asFloat64(item); ok {
					clamped := num
					if clamped < 576 {
						clamped = 576
					} else if clamped > 1460 {
						clamped = 1460
					}
					if clamped != num {
						logger.WarnContext(ctx, fmt.Sprintf("xray: kcp mtu %d is outside xray-core's accepted 576-1460 range; clamping to %d", int64(num), int64(clamped)))
					}
					out[k] = int64(clamped)
					continue
				}
			}
			out[k] = clampKcpMtu(ctx, logger, item)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = clampKcpMtu(ctx, logger, item)
		}
		return out
	default:
		return v
	}
}

// asFloat64 extracts a numeric value regardless of its concrete Go type. "mtu" reaches this code
// two different ways with two different concrete types: json.Unmarshal into map[string]any (the
// "Full Xray json" subscription-array path, and normalizeRangeObjects' own output) always produces
// float64, while ray2sing's link converters (getkcp) build the map directly in Go and hand it a
// plain int - a bare float64 type assertion only catches the first case.
func asFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

// xrayInternalOutboundTag is the fixed tag used inside the embedded, single-outbound xray-core
// instance. The manager/ray2sing-supplied tag (options.XConfig["tag"]) is discarded and replaced
// with this, since it's irrelevant beyond this package - sing-box's own tag (the outer Outbound.Tag)
// is what routing/UI actually see.
const xrayInternalOutboundTag = "out"

// abandonedConnBackstop is a last-resort ceiling on a single dispatch's lifetime, guarding only
// against a caller that dials and then never reads, writes, or closes the returned conn (a bug
// elsewhere leaking the dispatch goroutine forever). It is deliberately generous - long-lived
// proxied sessions (downloads, streams) are normal and must not be cut short by it - the primary,
// immediate cancellation path is the conn's Close() (wired below via cnc.ConnectionOnClose).
const abandonedConnBackstop = 30 * time.Minute

// drainTimeout bounds how long Close() waits for in-flight dispatches to unwind after
// cancellation, so a stuck dispatch can't hang shutdown indefinitely.
const drainTimeout = 5 * time.Second

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.XrayOutboundOptions](registry, C.TypeXray, New)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger   logger.ContextLogger
	instance *xcore.Instance
	handler  xoutbound.Handler

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	closeOnce sync.Once
}

// New builds a single-outbound, no-inbound xray-core instance from the raw xray-core outbound
// JSON carried in options.XConfig (protocol/settings/streamSettings, exactly the shape ray2sing's
// VlessXray/VmessXray/TrojanXray/DirectXray parsers, or a "Full Xray json" subscription's single
// outbound entry, produce), and dispatches sing-box Dial/ListenPacket calls straight to its
// outbound.Handler - bypassing xray-core's own routing/dispatcher entirely, since there is exactly
// one destination-less outbound and sing-box already decided to route here.
func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.XrayOutboundOptions) (adapter.Outbound, error) {
	// XConfig is the current field; DeprecatedXrayOutboundJson (xray_outbound_raw) is what the
	// Dart JSON editor's "xray" outbound template still seeds new outbounds with (and what
	// already-saved profiles on user devices contain), so fall back to it rather than erroring.
	rawConfig := options.XConfig
	if rawConfig == nil || len(*rawConfig) == 0 {
		rawConfig = options.DeprecatedXrayOutboundJson
	}
	if rawConfig == nil || len(*rawConfig) == 0 {
		return nil, E.New("xray: no outbound config provided (xconfig or xray_outbound_raw)")
	}

	normalized := normalizeRangeObjects(map[string]any(*rawConfig))
	normalized = clampKcpMtu(ctx, logger, normalized)
	rawOutbound, err := json.Marshal(normalized)
	if err != nil {
		return nil, E.Cause(err, "xray: marshal outbound config")
	}

	var outboundConf xconf.OutboundDetourConfig
	if err := json.Unmarshal(rawOutbound, &outboundConf); err != nil {
		return nil, E.Cause(err, "xray: parse outbound config")
	}
	outboundConf.Tag = xrayInternalOutboundTag
	if outboundConf.Protocol == "" {
		return nil, E.New("xray: outbound config is empty (missing protocol)")
	}

	xrayConfig := &xconf.Config{
		OutboundConfigs: []xconf.OutboundDetourConfig{outboundConf},
	}
	if logLevel := xrayLogLevel(options); logLevel != "" {
		xrayConfig.LogConfig = &xconf.LogConfig{LogLevel: logLevel, AccessLog: "none", ErrorLog: "none"}
	}

	coreConfig, err := xrayConfig.Build()
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
	installXrayLogForwarder(tag, logger)

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

	if options.DeprecatedFragment != nil {
		// xray_fragment (the JSON editor's TLS-hello fragment template) has no equivalent
		// applied by this embedded outbound - DirectXray's dialer/sockopt-based fragment
		// (ray2sing) is the supported path instead. Warn rather than silently doing nothing
		// that looks like it should matter.
		logger.WarnContext(ctx, "xray: xray_fragment is set but not applied by the embedded outbound; ignoring")
	}

	outboundCtx, cancel := context.WithCancel(ctx)
	return &Outbound{
		Adapter:  outbound.NewAdapter(C.TypeXray, tag, []string{"tcp", "udp"}, nil),
		logger:   logger,
		instance: instance,
		handler:  handler,
		ctx:      outboundCtx,
		cancel:   cancel,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dest := socksaddrToXrayDestination(destination, network == "udp")
	conn, err := h.dispatch(dest)
	if err != nil {
		return nil, err
	}
	h.logger.InfoContext(ctx, "xray outbound connection to ", destination)
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dest := socksaddrToXrayDestination(destination, true)
	conn, err := h.dispatch(dest)
	if err != nil {
		return nil, err
	}
	h.logger.InfoContext(ctx, "xray outbound packet connection to ", destination)
	return &packetConn{Conn: conn, remote: destination}, nil
}

func (h *Outbound) Close() error {
	var err error
	h.closeOnce.Do(func() {
		h.cancel()
		if h.instance != nil {
			err = h.instance.Close()
		}
		drained := make(chan struct{})
		go func() {
			h.wg.Wait()
			close(drained)
		}()
		select {
		case <-drained:
		case <-time.After(drainTimeout):
			h.logger.Warn("xray: timed out waiting for in-flight dispatches to drain on close")
		}
	})
	return err
}

// xrayLogLevel resolves the JSON editor's xdebug/xray_loglevel fields into an xray-core log
// level string, or "" to leave xray-core's own default (warning, console, no access log).
func xrayLogLevel(options option.XrayOutboundOptions) string {
	if options.DeprecatedLogLevel != nil && *options.DeprecatedLogLevel != "" {
		return *options.DeprecatedLogLevel
	}
	if options.XDebug {
		return "debug"
	}
	return ""
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

// dispatch wires up a pair of xray-core pipes into a transport.Link (handed to the outbound
// handler) and a net.Conn (handed back to sing-box), so writes on the net.Conn become reads on the
// handler's link.Reader, and the handler's link.Writer becomes reads on the net.Conn - the same
// buf.Reader/buf.Writer <-> net.Conn bridge xray-core's own proxy/loopback outbound uses to hand a
// dispatched connection back out as a plain net.Conn - then runs h.handler.Dispatch on it in a
// goroutine bounded by both h.ctx (cancelled on Close) and abandonedConnBackstop (a last-resort
// ceiling in case the caller dials and then never reads, writes, or closes the returned conn).
// Closing the returned conn cancels the dispatch's context immediately, the common path; the
// backstop only matters for a caller that never closes it at all. Either way h.wg accounts for
// the dispatch goroutine itself, not the conn's lifetime, so Close() can wait for it accurately.
func (h *Outbound) dispatch(dest xnet.Destination) (net.Conn, error) {
	if h.ctx.Err() != nil {
		return nil, E.New("xray: outbound is closing")
	}

	dispatchCtx, cancel := context.WithTimeout(h.ctx, abandonedConnBackstop)

	uplinkReader, uplinkWriter := xpipe.New()
	downlinkReader, downlinkWriter := xpipe.New()

	link := &xtransport.Link{Reader: uplinkReader, Writer: downlinkWriter}

	var outputOpt xcnc.ConnectionOption
	if dest.Network == xnet.Network_UDP {
		outputOpt = xcnc.ConnectionOutputMultiUDP(downlinkReader)
	} else {
		outputOpt = xcnc.ConnectionOutputMulti(downlinkReader)
	}
	conn := xcnc.NewConnection(
		xcnc.ConnectionInputMulti(uplinkWriter),
		outputOpt,
		xcnc.ConnectionOnClose(closerFunc(func() error {
			cancel()
			return nil
		})),
	)

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer cancel()
		h.handler.Dispatch(withXrayOutboundTarget(dispatchCtx, dest), link)
	}()

	return conn, nil
}

// closerFunc adapts a func() error to io.Closer, for cnc.ConnectionOnClose.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// packetConn adapts the connected, single-destination net.Conn newDispatch returns into a
// net.PacketConn - outbound UDP-through-a-proxy-tag is inherently tied to one destination for the
// life of the dispatch (ListenPacket is called once per sing-box UDP session/NAT entry, matching
// the destination it was dialed for), so ReadFrom always reports that fixed peer address, and
// WriteTo rejects any other target rather than silently misrouting it there.
type packetConn struct {
	net.Conn
	remote M.Socksaddr
}

func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(p)
	return n, c.remote.UDPAddr(), err
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if addr != nil && M.SocksaddrFromNet(addr) != c.remote {
		return 0, E.New("xray: packet conn is bound to ", c.remote, ", cannot write to ", addr)
	}
	return c.Conn.Write(p)
}
