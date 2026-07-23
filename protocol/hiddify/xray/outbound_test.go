package xray

import (
	"context"
	"io"
	"net"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
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

// TestKcpMtuBelowFloorClampsAndBuilds reproduces the exact "a.onionchips.sbs XDNS" outbound from a
// real hiddify-manager subscription (pulled from a user's live config export), which sets
// kcpSettings.mtu to 132 - a deliberately small value since this outbound only ever carries tiny
// DNS-sized UDP payloads (via the xdns finalmask). xray-core's own infra/conf.KCPConfig.Build()
// hard-rejects anything under 576 with "invalid mKCP MTU size: 132" - confirmed against both the
// exact vendored xray-core version and the current github.com/hiddify/xray-core source, so this
// isn't fixable by changing what JSON we generate, only by adapting what we send before it reaches
// that check. Without clampKcpMtu, this outbound fails to build at all.
func TestKcpMtuBelowFloorClampsAndBuilds(t *testing.T) {
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
}

// TestClampKcpMtuAboveCeiling checks the symmetric case (an oversized mtu gets pulled down to
// 1460) so the clamp isn't accidentally one-directional.
func TestClampKcpMtuAboveCeiling(t *testing.T) {
	in := map[string]any{
		"kcpSettings": map[string]any{"mtu": float64(9000)},
	}
	got := clampKcpMtu(context.Background(), log.NewNOPFactory().Logger(), in)
	want := map[string]any{
		"kcpSettings": map[string]any{"mtu": int64(1460)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clampKcpMtu mismatch:\ngot:  %#v\nwant: %#v", got, want)
	}
}

// TestClampKcpMtuInRangeUnchanged checks a value already inside [576, 1460] passes through as-is.
func TestClampKcpMtuInRangeUnchanged(t *testing.T) {
	in := map[string]any{
		"kcpSettings": map[string]any{"mtu": float64(1200)},
	}
	got := clampKcpMtu(context.Background(), log.NewNOPFactory().Logger(), in)
	want := map[string]any{
		"kcpSettings": map[string]any{"mtu": int64(1200)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clampKcpMtu mismatch:\ngot:  %#v\nwant: %#v", got, want)
	}
}

// TestClampKcpMtuHandlesPlainIntType guards against a real bug this exact test caught: a bare
// `item.(float64)` type assertion only matches values that arrived via json.Unmarshal (the "Full
// Xray json" subscription-array path). ray2sing's link converters (getkcp) build the map directly
// in Go and hand this a plain `int`, which silently failed the type assertion and skipped clamping
// entirely - meaning a link's own mtu=132 param would reach xray-core's build step unclamped and
// fail exactly the way the object-form-range and JSON-array cases already had.
func TestClampKcpMtuHandlesPlainIntType(t *testing.T) {
	in := map[string]any{
		"kcpSettings": map[string]any{"mtu": 132},
	}
	got := clampKcpMtu(context.Background(), log.NewNOPFactory().Logger(), in)
	want := map[string]any{
		"kcpSettings": map[string]any{"mtu": int64(576)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clampKcpMtu mismatch:\ngot:  %#v\nwant: %#v", got, want)
	}
}

// TestXdnsAndXicmpMasksBuildRealInstance guards xdns/xicmp support in the bundled Xray-core
// engine. The vendored fork this project used to pin (github.com/hiddify/xray-core, a single
// frozen commit with no tags or updates since) never implemented these mask types at all - only
// "salamander" was ever registered in its udpmaskLoader, confirmed against both that pinned commit
// and the live github.com/hiddify/xray-core main branch. Real upstream github.com/xtls/xray-core
// added xdns and xicmp (transport/internet/finalmask/xdns and .../xicmp) well before this - this
// project now depends on that real upstream directly (see go.mod) at a commit matching the schema
// hiddify-manager's own server templates generate against (a top-level "udpmasks" array of
// {"type","settings"} objects - an earlier schema revision used "finalmask"/{"udp":[...]} instead,
// which is why getFinalmask's shape matters - see ray2sing's xray_common.go).
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
					"udpmasks":    []any{c.mask},
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
