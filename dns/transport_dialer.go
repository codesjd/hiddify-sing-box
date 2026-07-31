package dns

import (
	"context"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func NewLocalDialer(ctx context.Context, options option.LocalDNSServerOptions) (N.Dialer, error) {
	return dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		DirectResolver: true,
	})
}

func NewRemoteDialer(ctx context.Context, options option.RemoteDNSServerOptions) (N.Dialer, error) {
	return dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
		DirectResolver: true,
		// DNS server detours commonly point at a caller-chosen fallback tag that's expected to
		// resolve to a plain direct outbound when the corresponding feature isn't configured
		// (e.g. hiddify's WARP-off passthrough) - that's an intentional no-op, not the kind of
		// outbound-routing misconfiguration NewDetour's empty-direct check exists to catch.
		DisableEmptyDirectCheck: true,
	})
}
