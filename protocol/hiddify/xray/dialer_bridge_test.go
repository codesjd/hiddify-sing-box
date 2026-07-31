package xray

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// resetInstallOutboundInterfaceExclusionOnceForTest lets each test observe its own fresh
// installOutboundInterfaceExclusion invocation - xray-core's dialer controller list is itself a
// process-wide singleton (see dialer_bridge.go), and every other test in this package constructing
// an Outbound via New() also exercises and consumes the "already installed" latch.
func resetInstallOutboundInterfaceExclusionOnceForTest(t *testing.T) {
	t.Helper()
	installOutboundInterfaceExclusionDone.Store(false)
}

// fakeNetworkManager stubs adapter.NetworkManager, overriding only what
// installOutboundInterfaceExclusion actually reads. Embedding the nil interface means any other
// method panics if called - a deliberate tripwire, since none should be for this test.
type fakeNetworkManager struct {
	adapter.NetworkManager
	autoDetectInterfaceCalls atomic.Int32
}

func (f *fakeNetworkManager) DefaultOptions() adapter.NetworkOptions { return adapter.NetworkOptions{} }
func (f *fakeNetworkManager) AutoDetectInterface() bool              { return true }
func (f *fakeNetworkManager) AutoDetectInterfaceFunc() control.Func {
	return func(network, address string, c syscall.RawConn) error {
		f.autoDetectInterfaceCalls.Add(1)
		return nil
	}
}
func (f *fakeNetworkManager) AutoRedirectOutputMarkFunc() control.Func { return nil }

// TestInstallOutboundInterfaceExclusionAppliesRealDial registers a fake NetworkManager (standing
// in for the real one box.go registers in production - see box.go's
// service.MustRegister[adapter.NetworkManager]) and checks that a real dial through the embedded
// xray-core "freedom" outbound actually invokes its AutoDetectInterfaceFunc - i.e. that
// RegisterDialerController really did wire this into xray-core's DefaultSystemDialer.controllers,
// not just that our own composition logic picked the right function to pass in. This is the
// regression guard for "embedded xray-core traffic never goes through sing-box's
// interface-exclusion/protect mechanism, so it gets captured by this app's own tun and loops back
// on itself instead of reaching the network" - see dialer_bridge.go's doc comment.
func TestInstallOutboundInterfaceExclusionAppliesRealDial(t *testing.T) {
	resetInstallOutboundInterfaceExclusionOnceForTest(t)

	fakeNM := &fakeNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), fakeNM)

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
				io.Copy(io.Discard, conn)
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

	adapterOutbound, err := New(ctx, nil, boxlog.NewNOPFactory().Logger(), "test-out", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ob := adapterOutbound.(*Outbound)
	defer ob.Close()

	conn, err := ob.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort(addr.IP.String(), uint16(addr.Port)))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for fakeNM.autoDetectInterfaceCalls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("AutoDetectInterfaceFunc was never invoked by xray-core's dialer - RegisterDialerController wiring is not reaching a real dial")
		}
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
}

// TestInstallOutboundInterfaceExclusionNoopsWithoutNetworkManager guards the common test/no-box
// context (context.Background(), as every other test in this package uses) against a panic or
// error - installOutboundInterfaceExclusion must degrade to xray-core's unmodified default dialer
// behavior rather than fail construction.
func TestInstallOutboundInterfaceExclusionNoopsWithoutNetworkManager(t *testing.T) {
	resetInstallOutboundInterfaceExclusionOnceForTest(t)
	installOutboundInterfaceExclusion(context.Background(), boxlog.NewNOPFactory().Logger())
}

// TestInstallOutboundInterfaceExclusionRetriesAfterAnEmptyFirstCall guards a real regression: this
// used to be gated by a sync.Once, so if the very first "xray" outbound ever constructed in the
// process raced ahead of box.go registering adapter.NetworkManager in context (plausible on a more
// involved startup path like TUN mode, which has more services to initialize before the router is
// fully configured, versus a plain proxy-mode config's minimal socks/http listener), that one
// unlucky empty call would permanently disable the exclusion for the rest of the process's life -
// every later "xray" outbound, including ones built well after the NetworkManager is fully ready,
// reconnects, and profile switches, would silently reproduce the tun-loopback hang forever. A
// context with no NetworkManager (matching the real "raced ahead of registration" case) must not
// prevent a later call, with a real one, from actually installing the exclusion.
func TestInstallOutboundInterfaceExclusionRetriesAfterAnEmptyFirstCall(t *testing.T) {
	resetInstallOutboundInterfaceExclusionOnceForTest(t)
	logger := boxlog.NewNOPFactory().Logger()

	// First call: no NetworkManager in context at all, exactly like an outbound racing ahead of
	// box startup - this must not be treated as a final answer.
	installOutboundInterfaceExclusion(context.Background(), logger)
	if installOutboundInterfaceExclusionDone.Load() {
		t.Fatalf("an empty first call (no NetworkManager) must not mark the exclusion as installed")
	}

	// Second call: NetworkManager is now available, as it would be once box startup actually
	// finishes - this must succeed rather than being permanently skipped by the first call.
	fakeNM := &fakeNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), fakeNM)
	installOutboundInterfaceExclusion(ctx, logger)
	if !installOutboundInterfaceExclusionDone.Load() {
		t.Fatalf("expected the second call (with a real NetworkManager) to install the exclusion - regression: an earlier empty call permanently disabled all future attempts")
	}
}
