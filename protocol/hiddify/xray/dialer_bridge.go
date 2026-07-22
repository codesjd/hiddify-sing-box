package xray

import (
	"context"
	"sync"

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
// process-wide - see transport/internet/system_dialer.go), so this only needs to run once
// regardless of how many "xray"-type outbounds exist in the config.
var installOutboundInterfaceExclusionOnce sync.Once

func installOutboundInterfaceExclusion(ctx context.Context, log logger.ContextLogger) {
	installOutboundInterfaceExclusionOnce.Do(func() {
		networkManager := service.FromContext[adapter.NetworkManager](ctx)
		if networkManager == nil {
			// No box-level network manager registered in this context (e.g. a unit test
			// constructing an Outbound directly against context.Background()) - nothing to
			// exclude from, and xray-core's default dialer behavior (plain net.Dialer, no
			// bind/protect) is unchanged from before this file existed.
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
			return
		}

		if err := xinternet.RegisterDialerController(fn); err != nil {
			// Only fails if xray-core's effective system dialer was already replaced wholesale
			// via UseAlternativeSystemDialer, which nothing in this codebase calls. If that ever
			// changes, surfacing a loud warning is far better than silently regressing back to
			// "embedded xray-core traffic disappears into the tun".
			log.Warn("xray: failed to install outbound interface exclusion: ", err)
		}
	})
}
