package xray

import (
	"context"
	"io"
	"net"
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
