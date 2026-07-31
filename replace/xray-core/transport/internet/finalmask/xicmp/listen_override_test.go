package xicmp

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
)

// fakePacketConn is a minimal IcmpPacketConn double used to prove ListenICMP is actually the
// seam NewConnClient dials through, without needing a real (possibly unavailable, see
// client_singlestack_test.go) ICMP socket.
type fakePacketConn struct {
	closed bool
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error)     { return 0, nil, net.ErrClosed }
func (f *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) { return len(b), nil }
func (f *fakePacketConn) Close() error                                 { f.closed = true; return nil }
func (f *fakePacketConn) SetDeadline(t time.Time) error                { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error            { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error           { return nil }

// TestNewConnClientDialsThroughListenICMPOverride proves NewConnClient actually calls the
// ListenICMP package var (not a hardcoded icmp.ListenPacket) for both the v4 and v6 dgram opens -
// the seam a Windows-only elevated-helper override depends on. Without this test, a future edit
// that reintroduced a direct icmp.ListenPacket call in NewConnClient (bypassing the override)
// would silently break the elevated-helper feature while every other xicmp test kept passing,
// since they don't install an override at all and so can't distinguish "used the override" from
// "used the real OS call that happens to also fail/succeed the same way".
func TestNewConnClientDialsThroughListenICMPOverride(t *testing.T) {
	var calledNetworks []string
	orig := ListenICMP
	defer func() { ListenICMP = orig }()
	ListenICMP = func(network, address string) (IcmpPacketConn, error) {
		calledNetworks = append(calledNetworks, network)
		return &fakePacketConn{}, nil
	}

	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to open loopback UDP conn for test fixture: %v", err)
	}
	defer raw.Close()

	conn, err := NewConnClient(&Config{DGRAM: true}, raw)
	if err != nil {
		t.Fatalf("NewConnClient: %v", err)
	}
	defer conn.Close()

	if len(calledNetworks) != 2 {
		t.Fatalf("expected ListenICMP to be called exactly twice (udp4, udp6), got %v", calledNetworks)
	}
	got := map[string]bool{calledNetworks[0]: true, calledNetworks[1]: true}
	if !got["udp4"] || !got["udp6"] {
		t.Fatalf(`expected calls for both "udp4" and "udp6", got %v`, calledNetworks)
	}
}

// TestNewConnClientDefaultListenICMPUsesRealSocket proves the *default* (non-overridden)
// ListenICMP still resolves to the exact same real OS call icmp.ListenPacket would make directly
// - i.e. the interface-type change on xicmpConnClient.icmp4/icmp6 (from the concrete
// *icmp.PacketConn to IcmpPacketConn) didn't change default behavior for platforms/processes that
// never install an override. This sandbox has neither working IPv4 nor IPv6 unprivileged ICMP
// (see client_singlestack_test.go's comment), so both are expected to fail identically here -
// asserting the two error strings match proves ListenICMP's default really is icmp.ListenPacket,
// not some other stub that happens to also return an error.
func TestNewConnClientDefaultListenICMPUsesRealSocket(t *testing.T) {
	_, wantErr := icmp.ListenPacket("udp4", "0.0.0.0")
	_, gotErr := ListenICMP("udp4", "0.0.0.0")
	if (wantErr == nil) != (gotErr == nil) {
		t.Fatalf("ListenICMP default diverged from icmp.ListenPacket: want err=%v, got err=%v", wantErr, gotErr)
	}
	if wantErr != nil && gotErr.Error() != wantErr.Error() {
		t.Fatalf("ListenICMP default diverged from icmp.ListenPacket:\nwant: %v\ngot:  %v", wantErr, gotErr)
	}
}
