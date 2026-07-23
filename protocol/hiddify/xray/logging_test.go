package xray

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// recordingLogger is a minimal logger.ContextLogger that records every InfoContext call, so tests
// can assert on what installXrayLogForwarder actually forwarded.
type recordingLogger struct {
	log.ContextLogger
	mu    sync.Mutex
	lines []string
}

func (r *recordingLogger) InfoContext(ctx context.Context, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, a := range args {
		if s, ok := a.(string); ok {
			b.WriteString(s)
		}
	}
	r.lines = append(r.lines, b.String())
}

func (r *recordingLogger) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

// TestXrayLogForwarderSurfacesRealDialFailure reproduces the exact observability gap a user hit:
// an xhttp outbound's connectivity test failed with nothing more informative than "io: read/write
// on closed pipe" in the app's own logs, because xray-core's Dispatch() suppresses that specific
// error class and had already generated (and then discarded) the real underlying reason as an
// internal log record. This builds a "freedom" outbound pointed at a closed local port - guaranteed
// to fail the dial immediately and deterministically, without any real network access - and checks
// that the real xray-core-internal failure message (not just "closed pipe") reaches our own logger.
func TestXrayLogForwarderSurfacesRealDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close() // guarantees the port is closed but was just valid, for a fast, deterministic refusal

	xconfig := map[string]any{
		"protocol": "freedom",
		"tag":      "test",
	}
	opts := option.XrayOutboundOptions{XConfig: &xconfig}

	rec := &recordingLogger{ContextLogger: log.NewNOPFactory().Logger()}
	adapterOutbound, err := New(context.Background(), nil, rec, "xdns-test-tag", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ob := adapterOutbound.(*Outbound)
	defer ob.Close()

	conn, err := ob.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort(addr.IP.String(), uint16(addr.Port)))
	if err == nil {
		// Reading forces the dispatch goroutine to actually run its retry/failure path before we
		// start checking for the forwarded diagnostic, instead of racing it.
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 16)
		conn.Read(buf)
		conn.Close()
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range rec.snapshot() {
			// The real diagnostic ("connection refused"), correctly tag-attributed - not just any
			// forwarded line, and not the generic "closed pipe" the caller sees at the net.Conn level.
			if strings.Contains(line, "xdns-test-tag") && strings.Contains(line, "connection refused") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected the real xray-core dial failure (connection refused) to be forwarded into our logger, got: %v", rec.snapshot())
}

// closedPort returns a TCP port guaranteed to refuse connections immediately and
// deterministically, without any real network access.
func closedPort(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	return addr
}

func newFreedomOutboundForTest(t *testing.T, tag string, rec *recordingLogger) *Outbound {
	t.Helper()
	xconfig := map[string]any{"protocol": "freedom", "tag": "test"}
	opts := option.XrayOutboundOptions{XConfig: &xconfig}
	adapterOutbound, err := New(context.Background(), nil, rec, tag, opts)
	if err != nil {
		t.Fatalf("New(%q): %v", tag, err)
	}
	return adapterOutbound.(*Outbound)
}

func dialClosedPort(ob *Outbound, addr *net.TCPAddr) {
	conn, err := ob.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort(addr.IP.String(), uint16(addr.Port)))
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 16)
		conn.Read(buf)
		conn.Close()
	}
}

func waitForLineContaining(t *testing.T, rec *recordingLogger, substrs ...string) string {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range rec.snapshot() {
			all := true
			for _, s := range substrs {
				if !strings.Contains(line, s) {
					all = false
					break
				}
			}
			if all {
				return line
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a line containing %v, got: %v", substrs, rec.snapshot())
	return ""
}

// TestXrayLogForwarderDoesNotMisattributeWithMultipleActiveInstances is the regression guard for
// the tag-misattribution bug found from a real user log: xray-core's log.Handler carries no
// per-instance context at all (see logging.go's doc comment), so with more than one embedded
// "xray" outbound alive at once, the old single-pointer scheme permanently mislabeled every
// instance's traffic with whichever outbound happened to be constructed last - observed as dozens
// of clearly-unrelated transports/servers all appearing under one single tag for an entire
// session. With two instances alive simultaneously, forwarded messages must not claim either
// specific tag; once back down to one, attribution must be trustworthy again.
func TestXrayLogForwarderDoesNotMisattributeWithMultipleActiveInstances(t *testing.T) {
	rec := &recordingLogger{ContextLogger: log.NewNOPFactory().Logger()}

	obA := newFreedomOutboundForTest(t, "outbound-a", rec)
	obB := newFreedomOutboundForTest(t, "outbound-b", rec)
	defer obA.Close()
	defer obB.Close()

	addr := closedPort(t)
	dialClosedPort(obA, addr)
	dialClosedPort(obB, addr)

	line := waitForLineContaining(t, rec, "connection refused")
	if strings.Contains(line, "outbound-a") || strings.Contains(line, "outbound-b") {
		t.Fatalf("expected an ambiguous-attribution line while 2 instances are alive, got a specific tag instead: %q", line)
	}
	if !strings.Contains(line, "ambiguous") {
		t.Fatalf("expected the ambiguous-attribution marker, got: %q", line)
	}

	// Back down to a single active instance - attribution should become trustworthy again.
	obB.Close()
	rec.mu.Lock()
	rec.lines = nil
	rec.mu.Unlock()

	dialClosedPort(obA, addr)
	line = waitForLineContaining(t, rec, "connection refused")
	if !strings.Contains(line, "outbound-a") {
		t.Fatalf("expected the single remaining instance's real tag once only one is alive, got: %q", line)
	}
	if strings.Contains(line, "ambiguous") {
		t.Fatalf("did not expect the ambiguous marker with only 1 instance alive, got: %q", line)
	}
}
