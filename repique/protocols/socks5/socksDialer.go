//Amongst few full socks5 clients implementation, I have to sigh for the big market of github 
//https://github.com/txthinking/socks5 worse
//https://github.com/0990/socks5       middle
//https://github.com/ginuerzh/gosocks5 better but not finished
//Below is a typical apple-pen-pineapple solution to minimum the binary size as well as a pretty implementation

package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"
	_ "unsafe"
)

/*******************************************************

Socks5 Client Library (implement 'UDP ASSOCIATE' in rfc1928)

*******************************************************/

// A Command represents a SOCKS command.
//go:linkname SocksCommand net/http.socksCommand
type SocksCommand int

// Wire protocol constants.
const (
	SocksCmdConnect SocksCommand = 0x01 // establishes an active-open forward proxy connection
	SockscmdBind    SocksCommand = 0x02 // establishes a passive-open forward proxy connection
	SockscmdUDP     SocksCommand = 0x03 // establishes a udp associate connection

	SocksAuthMethodNotRequired         socksAuthMethod = 0x00 // no authentication required
	SocksAuthMethodUsernamePassword    socksAuthMethod = 0x02 // use username/password

)


//go:linkname SocksCommand.String net/http.socksCommand.String
func (cmd SocksCommand) String() string

//go:linkname socksAuthMethod net/http.socksAuthMethod
type socksAuthMethod int

type SocksAuthMethod socksAuthMethod

// A Dialer holds SOCKS-specific options.
//go:linkname SocksDialer net/http.socksDialer
type SocksDialer struct {
	cmd          SocksCommand // either CmdConnect or cmdBind
	proxyNetwork string       // network between a proxy server and a client
	proxyAddress string       // proxy server address

	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)

	// AuthMethods specifies the list of request authentication
	// methods.
	// If empty, SOCKS client requests only AuthMethodNotRequired.
	AuthMethods []SocksAuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate func(context.Context, io.ReadWriter, socksAuthMethod) error
}

//go:linkname SocksUsernamePassword net/http.socksUserNamePassword
type SocksUsernamePassword struct {
	UserName string
	Password string
}

var (
	ErrBadAddrType = errors.New("Bad address type")
	sPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 576)
		},
	} 
	lPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 64*1024+262)
		},
	} 
)
/*
Address
 +------+----------+----------+
 | ATYP |   ADDR   |   PORT   |
 +------+----------+----------+
 |  1   | Variable |    2     |
 +------+----------+----------+
*/
const (
	AddrIPv4   uint8 = 1
	AddrDomain       = 3
	AddrIPv6         = 4
)

// An Addr represents a SOCKS-specific address.
// Either Name or IP is used exclusively.
//go:linkname socksAddr net/http.socksAddr
type socksAddr struct {
	Name string // fully-qualified domain name
	IP   net.IP
	Port int
}

//go:linkname (*socksAddr).Network net/http.(*socksAddr).Network
func (a *socksAddr) Network() string

//go:linkname (*socksAddr).String net/http.(*socksAddr).String
func (a *socksAddr) String() string

type SocksAddr struct {
	socksAddr
	Type uint8
}

func DecodeAddr(addr *SocksAddr, b []byte) error {
	addr.Type = b[0]
	pos := 1
	switch addr.Type {
	case AddrIPv4:
		addr.IP = net.IP(b[pos : pos+net.IPv4len])
		pos += net.IPv4len
	case AddrIPv6:
		addr.IP = net.IP(b[pos : pos+net.IPv6len])
		pos += net.IPv6len
	case AddrDomain:
		addrlen := int(b[pos])
		pos++
		addr.Name = string(b[pos : pos+addrlen])
		pos += addrlen
	default:
		return ErrBadAddrType
	}
	addr.Port = int(binary.BigEndian.Uint16(b[pos:]))
	return nil
}

func EncodeAddr(addr *SocksAddr, b []byte) (int, error) {
	b[0] = addr.Type
	pos := 1
	switch addr.Type {
	case AddrIPv4:
		pos += copy(b[pos:], addr.IP.To4())
	case AddrIPv6:
		pos += copy(b[pos:], addr.IP.To16())
	case AddrDomain:
		b[pos] = byte(len(addr.Name))
		pos++
		pos += copy(b[pos:], []byte(addr.Name))
	default:
		return 0, ErrBadAddrType
	}
	binary.BigEndian.PutUint16(b[pos:], uint16(addr.Port))
	pos += 2
	return pos, nil
}

/*
UDP request
 +----+------+------+----------+----------+----------+
 |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 +----+------+------+----------+----------+----------+
 | 2  |  1   |  1   | Variable |    2     | Variable |
 +----+------+------+----------+----------+----------+
*/
type UDPHeader struct {
	Rsv  uint16
	Frag uint8
	Addr *SocksAddr
}

func NewUDPHeader(rsv uint16, frag uint8, addr *SocksAddr) *UDPHeader {
	return &UDPHeader{
		Rsv:  rsv,
		Frag: frag,
		Addr: addr,
	}
}

func (h *UDPHeader) Write(w io.Writer) error {
	b := sPool.Get().([]byte)
	defer sPool.Put(b)

	binary.BigEndian.PutUint16(b[:2], h.Rsv)
	b[2] = h.Frag

	addr := h.Addr
	if addr == nil {
		addr = &SocksAddr{}
	}
	length, _ := EncodeAddr(addr, b[3:])

	_, err := w.Write(b[:3+length])
	return err
}

type UDPDatagram struct {
	Header *UDPHeader
	Data   *bytes.Reader
}

func NewUDPDatagram(header *UDPHeader, data []byte) *UDPDatagram {
	return &UDPDatagram{
		Header: header,
		Data:   bytes.NewReader(data),
	}
}

func ReadUDPDatagram(r io.Reader) (*UDPDatagram, error) {
	b := lPool.Get().([]byte)
	defer lPool.Put(b)

	n, err := io.ReadFull(r, b[:5])
	if err != nil {
		return nil, err
	}

	header := &UDPHeader{
		Rsv:  binary.BigEndian.Uint16(b[:2]),
		Frag: b[2],
	}

	atype := b[3]
	hlen := 0
	switch atype {
	case AddrIPv4:
		hlen = 10
	case AddrIPv6:
		hlen = 22
	case AddrDomain:
		hlen = 7 + int(b[4])
	default:
		return nil, ErrBadAddrType
	}

	dlen := int(header.Rsv)
	if dlen == 0 { // standard SOCKS5 UDP datagram
		extra, err := ioutil.ReadAll(r) // we assume no redundant data
		if err != nil {
			return nil, err
		}
		copy(b[n:], extra)
		n += len(extra) // total length
		dlen = n - hlen // data length
	} else { // extended feature, for UDP over TCP, using reserved field as data length
		if _, err := io.ReadFull(r, b[n:hlen+dlen]); err != nil {
			return nil, err
		}
		n = hlen + dlen
	}

	header.Addr = new(SocksAddr)
	if err := DecodeAddr(header.Addr, b[3:hlen]); err != nil {
		return nil, err
	}

	data := make([]byte, dlen)
	copy(data, b[hlen:n])

	d := &UDPDatagram{
		Header: header,
		Data:   bytes.NewReader(data),
	}

	return d, nil
}

func (d *UDPDatagram) Write(w io.Writer) (int, error) {
	buf, err := d.WriteBuf()
	if err != nil {
		return 0, err
	}
	c, err := buf.WriteTo(w)
	return int(c), err
}

func (d *UDPDatagram) WriteBuf() (*bytes.Buffer, error) {
	h := d.Header
	if h == nil {
		h = &UDPHeader{}
	}
	buf := &bytes.Buffer{}
	if err := h.Write(buf); err != nil {
		return nil, err
	}
	if _, err := d.Data.WriteTo(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

type UdpSocksConn struct {
	tcp             net.Conn
	udp             net.Conn
	raw             *UDPDatagram
	target          *SocksAddr
}

func NewUdpSocksConn(addr *SocksAddr, tcpconn, udpconn net.Conn) *UdpSocksConn {
	return &UdpSocksConn{tcp:tcpconn, udp:udpconn, target:addr}
}

func (c *UdpSocksConn) SetRealUDP(udp net.Conn) {
	last := c
	r, ok := c.udp.(*UdpSocksConn)
	for ;; {
		if ok && r != nil {
			last = r
			r, ok = r.udp.(*UdpSocksConn)
		} else {
			last.udp = udp
		}
	}
}

func (c *UdpSocksConn) LocalAddr() net.Addr {
	return c.tcp.LocalAddr()
}

func (c *UdpSocksConn) RemoteAddr() net.Addr {
	return c.tcp.RemoteAddr()
}

func (c *UdpSocksConn) SetDeadline(t time.Time) error {
	return c.udp.SetDeadline(t)
}

func (c *UdpSocksConn) SetReadDeadline(t time.Time) error {
	return c.udp.SetReadDeadline(t)
}

func (c *UdpSocksConn) SetWriteDeadline(t time.Time) error {
	return c.udp.SetWriteDeadline(t)
}

func (c *UdpSocksConn) Close() error {
	_ = c.tcp.Close()
	return c.udp.Close()
}

func (c *UdpSocksConn) Read(b []byte) (n int, err error) {
	if p, err := ReadUDPDatagram(c.udp); err != nil {
		return 0, err
	} else {
		c.raw = p
		return c.raw.Data.Read(b)
	}
}

func (c *UdpSocksConn) Write(b []byte) (n int, err error) {
	p := NewUDPDatagram(NewUDPHeader(0, 0, c.target), b)
	return p.Write(c.udp)
}

//Notice: port number and address of all zeros for 'UDP ASSOCIATE' do not work with this dated method in std libs
// otherwise parallel of dial and auth process is helpful to tunnel
//go:linkname (*SocksDialer).connect net/http.(*socksDialer).connect
func (d *SocksDialer) connect(ctx context.Context, c net.Conn, address string) (_ net.Addr, ctxErr error)

//go:linkname (*SocksUsernamePassword).Authenticate net/http.(*socksUsernamePassword).Authenticate
func (up *SocksUsernamePassword) Authenticate(ctx context.Context, rw io.ReadWriter, auth socksAuthMethod) error

func (d *SocksDialer) SetCMD(cmd SocksCommand) {
	d.cmd = cmd
}

func (d *SocksDialer) Connect(ctx context.Context, c net.Conn, network, address string) (*SocksAddr, error) {
	if c == nil || ctx == nil {
		panic("fault on calling (d *SocksDialer).Connect")
	}
	a, err := d.connect(ctx, c, address)
	if err != nil {
		c.Close()
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: err}
	}
	sa := &SocksAddr{socksAddr:*a.(*socksAddr)}
	if len(sa.Name) > 0 {
		sa.Type = AddrDomain
	} else if len(sa.IP) == net.IPv4len {
		sa.Type = AddrIPv4
	} else {
		sa.Type = AddrIPv6
	}
	return sa, nil
}


