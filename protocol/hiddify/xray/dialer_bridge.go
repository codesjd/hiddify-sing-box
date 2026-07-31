package xray

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	xinternet "github.com/xtls/xray-core/transport/internet"
)

// installOutboundInterfaceExclusion makes every embedded xray-core instance's outbound socket
// creation - both TCP dials and the UDP listen-then-connect xray-core's DefaultSystemDialer does
// internally, since RegisterDialerController's controllers are applied to both (see
// transport/internet/system_dialer.go in the vendored fork: the same d.controllers loop backs both
// dialer.Control and the UDP lc.Control) - go through the same interface-exclusion/protect
// mechanism every native sing-box outbound already gets automatically via common/dialer.NewDefault.
//
// Without this, on a system where this app's own tun is the default route, an embedded xray-core
// outbound's dial (a bare net.Dialer with no bind/protect/mark control) gets captured by that same
// tun and looped back into itself rather than ever reaching the real network - the connection just
// hangs until something times it out, rather than erroring, because nothing is actually wrong with
// the proxy config itself. Every sing-box-native outbound avoids exactly this via
// networkManager.ProtectFunc()/AutoDetectInterfaceFunc(), wired into its dialer's Control by
// common/dialer.NewDefault; the embedded xray-core outbound never went through that dialer at all,
// so it never got the same protection.
//
// xray-core's system dialer is a package-level singleton (RegisterDialerController appends to it
// process-wide - see transport/internet/system_dialer.go), so once a real (non-nil) controller is
// actually registered, it never needs to be registered again for the lifetime of the process,
// regardless of how many "xray"-type outbounds exist in the config or get reconstructed across
// profile switches/reconnects.
//
// Deliberately NOT a sync.Once: outbounds are constructed early in box startup, and on a more
// involved startup path (TUN mode: tun device creation, route table setup, more services to
// initialize before the router is fully configured) the very first "xray" outbound ever built in
// the process can race ahead of adapter.NetworkManager being registered in context, or ahead of
// its DefaultOptions/AutoDetectInterface being populated - both of which make this function
// legitimately produce nothing to install *at that moment*. A sync.Once here would treat that one
// unlucky early race as final, permanently disabling the exclusion for every later "xray" outbound
// for the rest of the process's life (including reconnects), silently reproducing exactly the
// tun-loopback hang this function exists to prevent - while plain, non-TUN "proxy mode" configs
// (simpler startup, no such race) look completely unaffected. Retrying on every construction until
// a real controller is actually installed closes that race without any real cost: once installed,
// installed.Load() short-circuits every later call to a single atomic read.
var (
	installOutboundInterfaceExclusionMu   sync.Mutex
	installOutboundInterfaceExclusionDone atomic.Bool
)

func installOutboundInterfaceExclusion(ctx context.Context, log logger.ContextLogger) {
	if installOutboundInterfaceExclusionDone.Load() {
		return
	}
	installOutboundInterfaceExclusionMu.Lock()
	defer installOutboundInterfaceExclusionMu.Unlock()
	if installOutboundInterfaceExclusionDone.Load() {
		return
	}

	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		// No box-level network manager registered in this context yet (e.g. a unit test
		// constructing an Outbound directly against context.Background(), or a real construction
		// that raced ahead of box startup) - nothing to exclude from right now. Do not mark this
		// done: the next "xray" outbound constructed (the next reconnect, the next profile switch)
		// gets another chance.
		return
	}

	var fn control.Func
	defaultOptions := networkManager.DefaultOptions()
	switch {
	case defaultOptions.BindInterface != "":
		fn = control.Append(fn, control.BindToInterface(networkManager.InterfaceFinder(), defaultOptions.BindInterface, -1))
	case networkManager.AutoDetectInterface():
		if service.FromContext[adapter.PlatformInterface](ctx) != nil {
			fn = control.Append(fn, networkManager.ProtectFunc())
		} else {
			fn = control.Append(fn, networkManager.AutoDetectInterfaceFunc())
		}
	}
	fn = control.Append(fn, networkManager.AutoRedirectOutputMarkFunc())
	if fn == nil {
		// networkManager exists but currently has nothing to install (e.g. AutoDetectInterface is
		// false and no bind_interface/mark is configured) - same reasoning as above: leave it
		// retryable rather than locking in a snapshot taken before options finished loading.
		return
	}

	if err := xinternet.RegisterDialerController(fn); err != nil {
		// Only fails if xray-core's effective system dialer was already replaced wholesale
		// via UseAlternativeSystemDialer, which nothing in this codebase calls. If that ever
		// changes, surfacing a loud warning is far better than silently regressing back to
		// "embedded xray-core traffic disappears into the tun". This particular failure mode
		// wouldn't change on a later retry, so it's fine to mark done rather than warn repeatedly.
		log.Warn("xray: failed to install outbound interface exclusion: ", err)
	}
	installOutboundInterfaceExclusionDone.Store(true)
}
