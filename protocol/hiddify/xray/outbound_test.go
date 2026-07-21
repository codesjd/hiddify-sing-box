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
