package awg

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// TestEndpointStartActuallyStartsUnderlyingDevice guards a real regression: Endpoint.Start used to
// be "if stage != adapter.StartStateStart { // return o.endpoint.Start(false) }" - a dead, commented-out
// line referencing a field name ("endpoint") that doesn't even exist on this struct (the embedded
// device is named Device) - meaning the embedded *awg.Device.Start was NEVER called on any stage.
// That leaves the real amneziawg-go device (d.awgDevice) nil forever: IpcSet (private/public keys,
// jc/jmin/jmax/s1-4/h1-4/i1-5) is never applied, the tun is never started, and the device is never
// brought up. The endpoint silently never connects - every dial through it times out - while
// reporting no error at all, matching a real user's "detected as awg but doesn't work (timeout)"
// report.
func TestEndpointStartActuallyStartsUnderlyingDevice(t *testing.T) {
	ctx := libbox.BaseContext(nil)

	options := option.AwgEndpointOptions{
		ListenPort: 0,
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		Peers: []option.AwgPeerOptions{
			{
				PublicKey:  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
				Address:    "192.0.2.1",
				Port:       51820,
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
		},
	}

	ep, err := NewEndpoint(ctx, nil, log.NewNOPFactory().Logger(), "test", options)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	endpoint, ok := ep.(*Endpoint)
	if !ok {
		t.Fatalf("expected *Endpoint, got %T", ep)
	}
	defer endpoint.Device.Close()

	if endpoint.Device.Started() {
		t.Fatalf("underlying device should not be started before Endpoint.Start is called")
	}
	if err := endpoint.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("Endpoint.Start(StartStateStart) failed: %v", err)
	}
	if !endpoint.Device.Started() {
		t.Fatalf("expected the embedded *awg.Device to be started after Endpoint.Start(StartStateStart) - regression: Endpoint.Start never delegates to the embedded Device.Start")
	}
}
