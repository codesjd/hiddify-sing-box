package xray

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	xconf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/kcp"
)

// TestDialEchoAndClose exercises the real dispatch path end to end (a "freedom" outbound
// proxying to a local TCP echo server) and checks that DialContext actually works and that
// closing the connection lets the dispatch goroutine unwind, rather than leaking it.
func TestDialEchoAndClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)

	xconfig := map[string]any{
		"protocol": "freedom",
		"tag":      "test",
	}
	opts := option.XrayOutboundOptions{XConfig: &xconfig}

	adapterOutbound, err := New(context.Background(), nil, log.NewNOPFactory().Logger(), "test-out", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ob := adapterOutbound.(*Outbound)
	defer ob.Close()

	runtime.Gosched()
	baseline := runtime.NumGoroutine()

	conn, err := ob.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort(addr.IP.String(), uint16(addr.Port)))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	message := []byte("hello xray outbound")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	received := make([]byte, len(message))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(received) != string(message) {
		t.Fatalf("echo mismatch: got %q, want %q", received, message)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close: %v", err)
	}

	// The dispatch goroutine should unwind shortly after Close(), not linger.
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.Gosched()
		if runtime.NumGoroutine() <= baseline+1 { // small slack for GC/runtime workers
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count did not settle after conn.Close(): baseline=%d, now=%d", baseline, runtime.NumGoroutine())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCloseWithoutDial ensures Close() on a freshly-constructed outbound that was never dialed
// doesn't hang or panic.
func TestCloseWithoutDial(t *testing.T) {
	xconfig := map[string]any{
		"protocol": "freedom",
		"tag":      "test",
	}
	opts := option.XrayOutboundOptions{XConfig: &xconfig}

	adapterOutbound, err := New(context.Background(), nil, log.NewNOPFactory().Logger(), "test-out", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ob := adapterOutbound.(*Outbound)

	done := make(chan error, 1)
	go func() { done <- ob.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return in time")
	}
}

// TestDialAfterClose ensures a dial attempted after Close() fails cleanly instead of dispatching
// into a closing instance.
func TestDialAfterClose(t *testing.T) {
	xconfig := map[string]any{
		"protocol": "freedom",
		"tag":      "test",
	}
	opts := option.XrayOutboundOptions{XConfig: &xconfig}

	adapterOutbound, err := New(context.Background(), nil, log.NewNOPFactory().Logger(), "test-out", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ob := adapterOutbound.(*Outbound)
	if err := ob.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = ob.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 1))
	if err == nil {
		t.Fatal("expected DialContext to fail after Close(), got nil error")
	}
}

// TestNormalizeRangeObjects checks the {"from": N, "to": M} -> "N-M" rewrite in isolation,
// including the from==to plain-integer case and that it recurses into nested maps/slices (the
// shape "extra.downloadSettings.xhttpSettings.xPaddingBytes" actually takes in real subscription
// output) without touching unrelated fields.
func TestNormalizeRangeObjects(t *testing.T) {
	in := map[string]any{
		"xPaddingBytes": map[string]any{"from": float64(100), "to": float64(1000)},
		"path":          "/x",
		"nested": map[string]any{
			"scMaxEachPostBytes": map[string]any{"from": float64(500), "to": float64(500)},
		},
		"list": []any{
			map[string]any{"cMaxReuseTimes": map[string]any{"from": float64(1), "to": float64(64)}},
		},
	}
	got := normalizeRangeObjects(in)
	want := map[string]any{
		"xPaddingBytes": "100-1000",
		"path":          "/x",
		"nested": map[string]any{
			"scMaxEachPostBytes": "500",
		},
		"list": []any{
			map[string]any{"cMaxReuseTimes": "1-64"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeRangeObjects mismatch:\ngot:  %#v\nwant: %#v", got, want)
	}
}

// TestObjectFormRangeConfigBuildsRealInstance reproduces the exact shape hiddify-manager's Xray
// JSON subscription export uses for xhttp padding (an object instead of xray-core's own
// "N-M"-string/plain-int form), including the nested extra.downloadSettings variant seen on TLS
// xhttp entries. xray-core's own infra/conf.Int32Range.UnmarshalJSON rejects the object form
// outright ("Invalid integer range, expected either string of form \"1-2\" or plain integer."), so
// prior to normalizeRangeObjects this outbound failed to build at all. Building and starting a
// real embedded xray-core instance (not just JSON-shape-checking) is the strongest available
// signal that the rewritten form is actually accepted.
func TestObjectFormRangeConfigBuildsRealInstance(t *testing.T) {
	xconfig := map[string]any{
		"protocol": "vless",
		"tag":      "test",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": "example.com",
					"port":    float64(443),
					"users": []any{
						map[string]any{"id": "6aca7d1d-632c-464f-b8de-f640962d89c7", "encryption": "none"},
					},
				},
			},
		},
		"streamSettings": map[string]any{
			"network":     "xhttp",
			"security":    "tls",
			"tlsSettings": map[string]any{"serverName": "example.com"},
			"xhttpSettings": map[string]any{
				"path": "/x",
				"host": "example.com",
				"mode": "auto",
				"extra": map[string]any{
					"downloadSettings": map[string]any{
						"address": "example.com",
						"port":    float64(443),
						"network": "xhttp",
						"xhttpSettings": map[string]any{
							"path":          "/x",
							"host":          "example.com",
							"mode":          "auto",
							"xPaddingBytes": map[string]any{"from": float64(100), "to": float64(1000)},
						},
						"security":    "tls",
						"tlsSettings": map[string]any{"serverName": "example.com"},
					},
				},
				"xPaddingBytes": map[string]any{"from": float64(500), "to": float64(500)},
			},
		},
	}
	opts := option.XrayOutboundOptions{XConfig: &xconfig}

	adapterOutbound, err := New(context.Background(), nil, log.NewNOPFactory().Logger(), "test-out", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ob := adapterOutbound.(*Outbound)
	defer ob.Close()
}

// TestKcpMtu132BuildsUnmodified reproduces the exact "a.onionchips.sbs XDNS" outbound from a real
// hiddify-manager subscription (pulled from a user's live config export), which sets
// kcpSettings.mtu to 132 - a deliberately small value chosen specifically to stay under the 224-
// byte hard ceiling xdns's own client.go encode() enforces on each raw mKCP segment
// (ray2sing/ray2sing/xrayjson.py's own comment: any mtu>=224 here "tunnels zero real traffic",
// since every oversized segment gets silently dropped rather than erroring).
//
// A prior version of this package had a clampKcpMtu step that force-raised any mtu below 576 up
// to 576, based on the belief that xray-core's own infra/conf.KCPConfig.Build() hard-rejects
// anything under 576. That belief was true of the OLD vendored github.com/hiddify/xray-core fork,
// but this project has since switched to real upstream github.com/xtls/xray-core (for xdns/xicmp
// support) - whose actual Build() floor is just 21 (confirmed directly against
// infra/conf/transport_internet.go: "if config.Mtu < 21 { ... }", no upper bound at all). Nobody
// revisited clampKcpMtu after that switch, so it kept silently overwriting the manager's
// deliberately-small mtu=132 with 576 - safely under xray-core's own build-time floor, but now
// well over xdns's separate 224-byte transmit-time ceiling, so every KCP segment carrying a real
// payload got silently dropped by the mask layer: the outbound built and "worked" by every check
// that only asked "did New() return an error", while genuinely carrying zero real traffic. This
// test asserts the *unmodified* mtu=132 reaches the built xray-core KCP transport settings, not
// just that New() succeeds.
func TestKcpMtu132BuildsUnmodified(t *testing.T) {
	xconfig := map[string]any{
		"protocol": "vless",
		"tag":      "proxy",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": "8.8.8.8",
					"port":    float64(53),
					"users": []any{
						map[string]any{"id": "6aca7d1d-632c-464f-b8de-f640962d89c7", "encryption": "none", "flow": "", "level": float64(8)},
					},
				},
			},
		},
		"streamSettings": map[string]any{
			"security": "none",
			"network":  "mkcp",
			"kcpSettings": map[string]any{
				"mtu": float64(132), "tti": float64(20), "uplinkCapacity": float64(5), "downlinkCapacity": float64(20), "congestion": false,
			},
			"finalmask": map[string]any{
				"udp": []any{
					map[string]any{
						"type": "xdns",
						"settings": map[string]any{
							"resolvers": []any{"a.onionchips.sbs+udp://8.8.8.8:53", "a.onionchips.sbs+udp://1.1.1.1:53"},
						},
					},
				},
			},
		},
	}
	opts := option.XrayOutboundOptions{XConfig: &xconfig}

	adapterOutbound, err := New(context.Background(), nil, log.NewNOPFactory().Logger(), "test-out", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	adapterOutbound.(*Outbound).Close()

	// The above only proves the outbound builds and starts - exactly what the old, wrongly-
	// clamped mtu=576 also did, while silently dropping all real traffic. Rebuild the same
	// streamSettings through the same normalizeRangeObjects + xconf.StreamConfig.Build() steps
	// New() uses internally and decode the actual KCP proto Xray-core ends up with, to prove the
	// mtu that reaches it is still 132 - not silently rewritten to something xdns can't carry.
	normalized := normalizeRangeObjects(xconfig["streamSettings"])
	raw, err := json.Marshal(normalized)
	if err != nil {
		t.Fatalf("marshal streamSettings: %v", err)
	}
	var sc xconf.StreamConfig
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatalf("unmarshal into xconf.StreamConfig: %v", err)
	}
	built, err := sc.Build()
	if err != nil {
		t.Fatalf("StreamConfig.Build(): %v", err)
	}
	if len(built.TransportSettings) != 1 {
		t.Fatalf("expected exactly 1 transport setting (mkcp), got %d", len(built.TransportSettings))
	}
	kcpMessage, err := built.TransportSettings[0].Settings.GetInstance()
	if err != nil {
		t.Fatalf("decode kcp settings: %v", err)
	}
	kcpConfig, ok := kcpMessage.(*kcp.Config)
	if !ok {
		t.Fatalf("expected *kcp.Config, got %T", kcpMessage)
	}
	if kcpConfig.Mtu != 132 {
		t.Fatalf("expected mtu to reach Xray-core unmodified as 132, got %d - a value this high defeats xdns's own 224-byte per-segment limit and silently drops all real traffic", kcpConfig.Mtu)
	}
}

// TestXdnsAndXicmpMasksBuildRealInstance guards xdns/xicmp support in the bundled Xray-core
// engine. The vendored fork this project used to pin (github.com/hiddify/xray-core, a single
// frozen commit with no tags or updates since) never implemented these mask types at all - only
// "salamander" was ever registered in its udpmaskLoader, confirmed against both that pinned commit
// and the live github.com/hiddify/xray-core main branch. Real upstream github.com/xtls/xray-core
// added xdns and xicmp (transport/internet/finalmask/xdns and .../xicmp) well before this - this
// project now depends on that real upstream directly (see go.mod).
//
// The mask lives under a top-level "finalmask": {"udp": [...]} object - confirmed directly
// against infra/conf/transport_internet.go's StreamConfig struct ("FinalMask *FinalMask
// `json:"finalmask"`", where FinalMask.Udp is the array), NOT a top-level "udpmasks" key. An
// earlier version of this test (and of ray2sing's getFinalmask) used "udpmasks" - json.Unmarshal
// into xconf.OutboundDetourConfig silently ignores unrecognized keys, so that variant still built
// and started an instance without error, just as one running plain unmasked KCP - a false pass
// that looked like proof this worked. See TestFinalmaskKeyReachesXrayCoreStreamConfig below,
// which asserts the actual Udpmasks count instead of only "did New() return an error".
func TestXdnsAndXicmpMasksBuildRealInstance(t *testing.T) {
	cases := []struct {
		name string
		mask map[string]any
	}{
		{
			name: "xdns",
			mask: map[string]any{
				"type":     "xdns",
				"settings": map[string]any{"domains": []any{"a.onionchips.sbs"}},
			},
		},
		{
			name: "xicmp",
			mask: map[string]any{
				"type":     "xicmp",
				"settings": map[string]any{"dgram": true, "ips": []any{}},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			xconfig := map[string]any{
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": "8.8.8.8",
							"port":    float64(53),
							"users": []any{
								map[string]any{"id": "6aca7d1d-632c-464f-b8de-f640962d89c7", "encryption": "none"},
							},
						},
					},
				},
				"streamSettings": map[string]any{
					"network":     "mkcp",
					"kcpSettings": map[string]any{"mtu": float64(576)},
					"finalmask":   map[string]any{"udp": []any{c.mask}},
				},
			}
			opts := option.XrayOutboundOptions{XConfig: &xconfig}
			adapterOutbound, err := New(context.Background(), nil, log.NewNOPFactory().Logger(), "test-out", opts)
			if err != nil {
				t.Fatalf("real xray-core instance failed to build/start with a %q mask: %v", c.name, err)
			}
			adapterOutbound.(*Outbound).Close()
		})
	}
}

// TestFinalmaskKeyReachesXrayCoreStreamConfig directly proves which top-level JSON key Xray-core's
// own infra/conf.StreamConfig actually recognizes for masks, by running the exact same
// marshal/unmarshal/Build() steps New() uses and inspecting the resulting Udpmasks count - not
// just whether an error was returned. "udpmasks" (an earlier, incorrect assumption baked into both
// this test and ray2sing's getFinalmask at one point) is confirmed here to be silently dropped:
// StreamConfig has no field tagged that way, so json.Unmarshal ignores it without error, and
// Build() produces zero masks. "finalmask": {"udp": [...]} is the one Xray-core's own struct tag
// declares, and is confirmed here to actually populate Udpmasks.
func TestFinalmaskKeyReachesXrayCoreStreamConfig(t *testing.T) {
	mask := map[string]any{
		"type":     "xdns",
		"settings": map[string]any{"domains": []any{"a.onionchips.sbs"}},
	}
	buildUdpmaskCount := func(t *testing.T, streamSettings map[string]any) int {
		t.Helper()
		normalized := normalizeRangeObjects(map[string]any{"streamSettings": streamSettings})
		raw, err := json.Marshal(normalized)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var oc xconf.OutboundDetourConfig
		if err := json.Unmarshal(raw, &oc); err != nil {
			t.Fatalf("unmarshal into xconf.OutboundDetourConfig: %v", err)
		}
		built, err := oc.StreamSetting.Build()
		if err != nil {
			t.Fatalf("StreamSetting.Build(): %v", err)
		}
		return len(built.Udpmasks)
	}

	t.Run("finalmask key is recognized", func(t *testing.T) {
		got := buildUdpmaskCount(t, map[string]any{
			"network":   "mkcp",
			"finalmask": map[string]any{"udp": []any{mask}},
		})
		if got != 1 {
			t.Fatalf(`expected "finalmask":{"udp":[...]} to register 1 udpmask, got %d`, got)
		}
	})

	t.Run("udpmasks key is silently ignored", func(t *testing.T) {
		got := buildUdpmaskCount(t, map[string]any{
			"network":  "mkcp",
			"udpmasks": []any{mask},
		})
		if got != 0 {
			t.Fatalf(`expected a top-level "udpmasks" key to be silently ignored (0 udpmasks), got %d - if this now passes, Xray-core's schema has changed and getFinalmask/this test need updating together`, got)
		}
	})
}
