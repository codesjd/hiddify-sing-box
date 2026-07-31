package xicmp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"time"
	_ "unsafe"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var pool = sync.Pool{
	New: func() any {
		return make([]byte, finalmask.UDPSize)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
	err  error
}

// IcmpPacketConn is the exact subset of *icmp.PacketConn's methods xicmpConnClient actually calls
// (audited across this file: ReadFrom in recv4/recv6, WriteTo, Close, SetDeadline/SetReadDeadline/
// SetWriteDeadline - LocalAddr is only ever called on the outer raw conn, never on icmp4/icmp6).
// *icmp.PacketConn satisfies this structurally with no changes. Defining it lets ListenICMP below
// be overridden by an importer (e.g. hiddify-core, only on Windows, only when not already running
// elevated) to hand back a non-OS-backed implementation - such as one proxying packets through a
// separate elevated helper process - without this package needing any awareness of how or why.
// Exported (despite otherwise being purely internal plumbing) because Go function-type identity
// requires exact type matches: an external package assigning its own function value to
// ListenICMP has to name this return type in its own function literal, which is only possible if
// the type itself is exported - interface satisfaction being structural doesn't help here, since
// this is about the *declared* function type, not which concrete type ultimately gets returned.
type IcmpPacketConn interface {
	ReadFrom(b []byte) (n int, addr net.Addr, err error)
	WriteTo(b []byte, addr net.Addr) (n int, err error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// ListenICMP opens the underlying ICMP socket. Defaults to the real OS socket via
// golang.org/x/net/icmp; overridable per the IcmpPacketConn doc comment above.
var ListenICMP = func(network, address string) (IcmpPacketConn, error) {
	return icmp.ListenPacket(network, address)
}

type xicmpConnClient struct {
	conn     net.PacketConn
	icmp4    IcmpPacketConn
	icmp6    IcmpPacketConn
	udp      bool
	ips      []netip.Addr
	clientID [8]byte
	id       int
	seq      int
	readCh   chan packet
	closedCh chan struct{}
	mu       sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	var icmp4, icmp6 IcmpPacketConn
	var err4, err6 error
	if c.DGRAM {
		icmp4, err4 = ListenICMP("udp4", "0.0.0.0")
		icmp6, err6 = ListenICMP("udp6", "::")
	} else {
		icmp4, err4 = ListenICMP("ip4:icmp", "0.0.0.0")
		icmp6, err6 = ListenICMP("ip6:ipv6-icmp", "::")
	}
	// Only fail if NEITHER family is usable. A host with no IPv6 configured (very common,
	// especially on Windows clients) or one where only the v4 or v6 unprivileged ICMP
	// protocol is registered would otherwise be unable to use xicmp at all, even though one
	// working family is enough to carry traffic - every other method on xicmpConnClient below
	// is nil-guarded against whichever of icmp4/icmp6 didn't come up.
	if err4 != nil && err6 != nil {
		return nil, errors.Combine(err4, err6)
	}
	if err4 != nil {
		errors.LogInfo(context.Background(), "xicmp: ipv4 unavailable, continuing with ipv6 only: ", err4)
		icmp4 = nil
	}
	if err6 != nil {
		errors.LogInfo(context.Background(), "xicmp: ipv6 unavailable, continuing with ipv4 only: ", err6)
		icmp6 = nil
	}

	ips := make([]netip.Addr, 0, len(c.IPs))
	for _, ip := range c.IPs {
		ips = append(ips, netip.MustParseAddr(ip))
	}

	var clientID [8]byte
	common.Must2(rand.Read(clientID[:]))

	conn := &xicmpConnClient{
		conn:     raw,
		icmp4:    icmp4,
		icmp6:    icmp6,
		udp:      c.DGRAM,
		ips:      ips,
		clientID: clientID,
		id:       mathrand.Intn(65536),
		seq:      1,
		readCh:   make(chan packet),
		closedCh: make(chan struct{}),
	}

	go conn.recv4()
	go conn.recv6()

	return conn, nil
}

func (c *xicmpConnClient) ring(a, b uint16) uint16 {
	return min(a-b, b-a)
}

func (c *xicmpConnClient) closed() bool {
	select {
	case <-c.closedCh:
		return true
	default:
		return false
	}
}

func (c *xicmpConnClient) recv4() {
	if c.icmp4 == nil {
		return
	}

	var b [finalmask.UDPSize]byte

	for {
		if c.closed() {
			return
		}

		n, addr, err := c.icmp4.ReadFrom(b[:])
		if err != nil {
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{
					err: err,
				}:
				case <-c.closedCh:
					return
				}
			}
			continue
		}

		msg, err := icmp.ParseMessage(1, b[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		// errors.LogDebug(context.Background(), "id ", echo.ID, " seq ", echo.Seq, " addr ", addr)

		if !c.udp && echo.ID != c.id {
			continue
		}

		if c.ring(uint16(echo.Seq), uint16(c.seq)) > 1000 {
			continue
		}

		if len(echo.Data) > 8 && bytes.Equal(echo.Data[:8], c.clientID[:]) {
			continue
		}

		p := pool.Get().([]byte)[:len(echo.Data)]
		copy(p, echo.Data)

		if !c.udp {
			addr = &net.UDPAddr{IP: addr.(*net.IPAddr).IP}
		}

		select {
		case c.readCh <- packet{
			p:    p,
			addr: addr,
		}:
		case <-c.closedCh:
			pool.Put(p)
			return
		}
	}
}

func (c *xicmpConnClient) recv6() {
	if c.icmp6 == nil {
		return
	}

	var b [finalmask.UDPSize]byte

	for {
		if c.closed() {
			break
		}

		n, addr, err := c.icmp6.ReadFrom(b[:])
		if err != nil {
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{
					err: err,
				}:
				case <-c.closedCh:
					return
				}
			}
			continue
		}

		msg, err := icmp.ParseMessage(58, b[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv6.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		// errors.LogDebug(context.Background(), "id ", echo.ID, " seq ", echo.Seq, " addr ", addr)

		if !c.udp && echo.ID != c.id {
			continue
		}

		if c.ring(uint16(echo.Seq), uint16(c.seq)) > 1000 {
			continue
		}

		if len(echo.Data) > 8 && bytes.Equal(echo.Data[:8], c.clientID[:]) {
			continue
		}

		p := pool.Get().([]byte)[:len(echo.Data)]
		copy(p, echo.Data)

		if !c.udp {
			addr = &net.UDPAddr{IP: addr.(*net.IPAddr).IP}
		}

		select {
		case c.readCh <- packet{
			p:    p,
			addr: addr,
		}:
		case <-c.closedCh:
			pool.Put(p)
			return
		}
	}
}

func (c *xicmpConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-c.readCh:
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p)
		}
		return n, packet.addr, packet.err
	case <-c.closedCh:
		return 0, nil, io.EOF
	}
}

func (c *xicmpConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p)+16 > finalmask.UDPSize {
		errors.LogError(context.Background(), "drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	c.mu.Lock()
	seq := c.seq
	c.seq += 1
	c.seq %= 65536
	c.mu.Unlock()

	ip := addr.(*net.UDPAddr).IP
	if len(c.ips) > 0 {
		ip = c.ips[mathrand.Intn(len(c.ips))].AsSlice()
	}

	if c.udp {
		addr = &net.UDPAddr{IP: ip}
	} else {
		addr = &net.IPAddr{IP: ip}
	}

	b := pool.Get().([]byte)[:finalmask.UDPSize]
	defer pool.Put(b)

	copy(b[8:], c.clientID[:])
	copy(b[16:], p)

	if ip.To4() != nil {
		if c.icmp4 == nil {
			return 0, errors.New("xicmp: ipv4 unavailable on this host")
		}
		b = marshal(b, ipv4.ICMPTypeEcho, c.id, seq, 8+len(p))
		_, err = c.icmp4.WriteTo(b, addr)
	} else {
		if c.icmp6 == nil {
			return 0, errors.New("xicmp: ipv6 unavailable on this host")
		}
		b = marshal(b, ipv6.ICMPTypeEchoRequest, c.id, seq, 8+len(p))
		_, err = c.icmp6.WriteTo(b, addr)
	}

	if err != nil {
		errors.LogErrorInner(context.Background(), err, "xicmp write")
		return 0, err
	}

	return len(p), nil
}

func (c *xicmpConnClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closedCh)
	if c.icmp4 != nil {
		_ = c.icmp4.Close()
	}
	if c.icmp6 != nil {
		_ = c.icmp6.Close()
	}
	_ = c.conn.Close()
	return nil
}

func (c *xicmpConnClient) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *xicmpConnClient) SetDeadline(t time.Time) error {
	if c.icmp4 != nil {
		_ = c.icmp4.SetDeadline(t)
	}
	if c.icmp6 != nil {
		_ = c.icmp6.SetDeadline(t)
	}
	return nil
}

func (c *xicmpConnClient) SetReadDeadline(t time.Time) error {
	if c.icmp4 != nil {
		_ = c.icmp4.SetReadDeadline(t)
	}
	if c.icmp6 != nil {
		_ = c.icmp6.SetReadDeadline(t)
	}
	return nil
}

func (c *xicmpConnClient) SetWriteDeadline(t time.Time) error {
	if c.icmp4 != nil {
		_ = c.icmp4.SetWriteDeadline(t)
	}
	if c.icmp6 != nil {
		_ = c.icmp6.SetWriteDeadline(t)
	}
	return nil
}

//go:linkname checksum golang.org/x/net/icmp.checksum
func checksum(b []byte) uint16

func marshal(b []byte, typ icmp.Type, id, seq int, dataLen int) []byte {
	is4 := false
	switch typ := typ.(type) {
	case ipv4.ICMPType:
		is4 = true
		b[0] = byte(typ)
	case ipv6.ICMPType:
		b[0] = byte(typ)
	default:
		panic(fmt.Sprintf("%T %v", typ, typ))
	}
	clear(b[1:4])
	binary.BigEndian.PutUint16(b[4:], uint16(id))
	binary.BigEndian.PutUint16(b[6:], uint16(seq))
	if is4 {
		s := checksum(b[:8+dataLen])
		b[2] ^= byte(s)
		b[3] ^= byte(s >> 8)
	}
	return b[:8+dataLen]
}
