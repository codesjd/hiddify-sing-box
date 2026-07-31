package xicmp

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestXicmpConnClientToleratesMissingFamily guards against a real upstream bug: NewConnClient
// used to require BOTH icmp.ListenPacket("udp4", ...) and icmp.ListenPacket("udp6", ...) to
// succeed, returning an error (and refusing the outbound entirely) if either failed - even
// though a single working family is enough to carry traffic. That's a common situation: many
// Windows hosts have no IPv6 configured for raw/unprivileged ICMP at all (this exact failure -
// "socket: The requested protocol has not been configured into the system, or no implementation
// for it exists." - was observed on a real client), and this sandbox itself can't open either
// family (no CAP_NET_RAW / ping_group_range for v4, no IPv6 support for v6 - see icmp probe used
// while diagnosing this).
//
// NewConnClient now only fails if NEITHER family works, and stores nil for whichever one
// didn't come up. That makes every other method on xicmpConnClient a nil-pointer-dereference
// hazard if it isn't guarded - this test constructs a client with both icmp4 and icmp6 nil (the
// most nil-hostile case any real single-stack client would exercise) and calls each method that
// touches those fields, asserting none of them panic.
func TestXicmpConnClientToleratesMissingFamily(t *testing.T) {
	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to open loopback UDP conn for test fixture: %v", err)
	}
	defer raw.Close()

	c := &xicmpConnClient{
		conn:     raw,
		icmp4:    nil,
		icmp6:    nil,
		udp:      true,
		ips:      nil,
		id:       1,
		seq:      1,
		readCh:   make(chan packet),
		closedCh: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.recv4()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recv4 did not return immediately with icmp4 == nil")
	}

	done = make(chan struct{})
	go func() {
		defer close(done)
		c.recv6()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recv6 did not return immediately with icmp6 == nil")
	}

	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline with both families nil: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline with both families nil: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline with both families nil: %v", err)
	}

	v4Addr := &net.UDPAddr{IP: netip.MustParseAddr("192.0.2.1").AsSlice()}
	if _, err := c.WriteTo([]byte("hi"), v4Addr); err == nil {
		t.Fatal("expected WriteTo an ipv4 destination to fail cleanly with icmp4 == nil, got no error")
	}

	v6Addr := &net.UDPAddr{IP: netip.MustParseAddr("2001:db8::1").AsSlice()}
	if _, err := c.WriteTo([]byte("hi"), v6Addr); err == nil {
		t.Fatal("expected WriteTo an ipv6 destination to fail cleanly with icmp6 == nil, got no error")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close with both families nil: %v", err)
	}
}
