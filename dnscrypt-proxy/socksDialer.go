//Amongst few full socks5 clients implementation, I have to sigh for the big market of github 
//https://github.com/txthinking/socks5 worse
//https://github.com/0990/socks5       middle
//https://github.com/ginuerzh/gosocks5 better but not finished
//Below is a typical apple-pen-pineapple solution to minimum the binary size as well as a pretty implementation

package main

import (
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"sync"
	"time"
	_ "unsafe"
)


const (
	socksAuthMethodNotRequired         socksAuthMethod = 0x00 // no authentication required
	socksAuthMethodUsernamePassword    socksAuthMethod = 0x02 // use username/password
)

// A Command represents a SOCKS command.
type socksCommand int
// An AuthMethod represents a SOCKS authentication method.
type socksAuthMethod int

// A Dialer holds SOCKS-specific options.
type socksDialer struct {
	cmd          socksCommand // either CmdConnect or cmdBind
	proxyNetwork string       // network between a proxy server and a client
	proxyAddress string       // proxy server address

	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)

	// AuthMethods specifies the list of request authentication
	// methods.
	// If empty, SOCKS client requests only AuthMethodNotRequired.
	AuthMethods []socksAuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate func(context.Context, io.ReadWriter, socksAuthMethod) error
}

type socksUsernamePassword struct {
	Username string
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

type Addr struct {
	Type uint8
	Host string
	Port uint16
}

func NewAddr(sa string) (addr *Addr, err error) {
	host, sport, err := net.SplitHostPort(sa)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return nil, err
	}

	addr = &Addr{
		Type: AddrDomain,
		Host: host,
		Port: uint16(port),
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			addr.Type = AddrIPv4
		} else {
			addr.Type = AddrIPv6
		}
	}

	return
}

func (addr *Addr) Decode(b []byte) error {
	addr.Type = b[0]
	pos := 1
	switch addr.Type {
	case AddrIPv4:
		addr.Host = net.IP(b[pos : pos+net.IPv4len]).String()
		pos += net.IPv4len
	case AddrIPv6:
		addr.Host = net.IP(b[pos : pos+net.IPv6len]).String()
		pos += net.IPv6len
	case AddrDomain:
		addrlen := int(b[pos])
		pos++
		addr.Host = string(b[pos : pos+addrlen])
		pos += addrlen
	default:
		return ErrBadAddrType
	}

	addr.Port = binary.BigEndian.Uint16(b[pos:])

	return nil
}

func (addr *Addr) Encode(b []byte) (int, error) {
	b[0] = addr.Type
	pos := 1
	switch addr.Type {
	case AddrIPv4:
		ip4 := net.ParseIP(addr.Host).To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		pos += copy(b[pos:], ip4)
	case AddrDomain:
		b[pos] = byte(len(addr.Host))
		pos++
		pos += copy(b[pos:], []byte(addr.Host))
	case AddrIPv6:
		ip16 := net.ParseIP(addr.Host).To16()
		if ip16 == nil {
			ip16 = net.IPv6zero.To16()
		}
		pos += copy(b[pos:], ip16)
	default:
		b[0] = AddrIPv4
		copy(b[pos:pos+4], net.IPv4zero.To4())
		pos += 4
	}
	binary.BigEndian.PutUint16(b[pos:], addr.Port)
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
	Addr *Addr
}

func NewUDPHeader(rsv uint16, frag uint8, addr *Addr) *UDPHeader {
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
		addr = &Addr{}
	}
	length, _ := addr.Encode(b[3:])

	_, err := w.Write(b[:3+length])
	return err
}

type UDPDatagram struct {
	Header *UDPHeader
	Data   []byte
}

func NewUDPDatagram(header *UDPHeader, data []byte) *UDPDatagram {
	return &UDPDatagram{
		Header: header,
		Data:   data,
	}
}

func ReadUDPDatagram(r io.Reader) (*UDPDatagram, error) {
	b := lPool.Get().([]byte)
	defer lPool.Put(b)

	// when r is a streaming (such as TCP connection), we may read more than the required data,
	// but we don't know how to handle it. So we use io.ReadFull to instead of io.ReadAtLeast
	// to make sure that no redundant data will be discarded.
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

	header.Addr = new(Addr)
	if err := header.Addr.Decode(b[3:hlen]); err != nil {
		return nil, err
	}

	data := make([]byte, dlen)
	copy(data, b[hlen:n])

	d := &UDPDatagram{
		Header: header,
		Data:   data,
	}

	return d, nil
}

func (d *UDPDatagram) Write(w io.Writer) error {
	buf, err := d.WriteBuf()
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(w)
	return err
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
	if _, err := buf.Write(d.Data); err != nil {
		return nil, err
	}
	return buf, nil
}



type SocksConn struct {
	conn         net.Conn
	udp          net.Conn
	addrs        list.List
}

func (c *SocksConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *SocksConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *SocksConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *SocksConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *SocksConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *SocksConn) Close() error {
	return c.conn.Close()
}

func (c *SocksConn) Read(b []byte) (n int, err error) {
if c.udp != nil {


}

	return 0, nil
}

func (c *SocksConn) Write(b []byte) (n int, err error) {
	return 0, nil
}

//go:linkname connect http.connect
func (d *socksDialer) connect(ctx context.Context, c net.Conn, address string) (_ net.Addr, ctxErr error)

//go:linkname Authenticate http.Authenticate
func (up *socksUsernamePassword) Authenticate(ctx context.Context, rw io.ReadWriter, auth socksAuthMethod) error

func (d *socksDialer) Connect(ctx context.Context, network, c net.Conn, address string) (net.Conn, error) {
	return nil, nil
}


