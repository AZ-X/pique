package common

import (
	"container/ring"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	_ "unsafe"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	
	stamps "stammel"
)
//only if deep debug e.g. raw msg dumping
const Program_dbg_full = false

func Program_dbg_full_log(args ...interface{}) {
	if Program_dbg_full {
		format := args[0].(string)
		var params []interface{}
		if len(args) > 1 {
			params = args[1:]
			dlog.Debugf(format, params...)
		} else {
			dlog.Debug(format)
		}
	}
}

const (
	MinDNSPacketSize        = 12 + 5
	MaxDNSPacketSize        = dns.MaxMsgSize
	MaxDNSUDPPacketSize     = dns.DefaultMsgSize
	MaxDNSUDPSafePacketSize = 1252
	STAR                    = "*"
	Delimiter               = ";"
)

type RegisteredServer struct {
	Name        string
	Stamp       *stamps.ServerStamp
}

/*---------------------------------------------------------------------------------------

    Network related types, funcs authored by repique

/*--------------------------------------------------------------------------------------*/

type TLSContext struct {
	context.Context
}

type Endpoint struct {
	*net.IPAddr
	Port                      int
}

type EPRing struct {
	*ring.Ring
	*Endpoint
	order                     int `aka name`
}

func (e *EPRing) Order() string {
	return strconv.Itoa(e.order)
}

func (e *EPRing) Next() *EPRing {
	return e.Ring.Next().Value.(*EPRing)
}

func LinkEPRing(endpoints ...*Endpoint) *EPRing {
	var cur *EPRing = nil
	for i , endpoint := range endpoints {
		tmp := &EPRing{}
		tmp.Ring = ring.New(1)
		tmp.Value = tmp
		tmp.order = i + 1
		tmp.Endpoint = endpoint
		if cur != nil {
			cur.Link(tmp.Ring)
		}
		cur = tmp
	}
	return cur
}

func (e *Endpoint) String() string {
	return net.JoinHostPort(e.IPAddr.String(), strconv.Itoa(e.Port))
}

//go:linkname ParseIPZone net.parseIPZone
func ParseIPZone(s string) (net.IP, string)

func ResolveEndpoint(hostport string) (*Endpoint, error) {
	host, port, err := ExtractHostAndPort(hostport, 0)
	if err != nil {
		return nil, err
	}
	ip, zone := ParseIPZone(host)
	if ip == nil {
		return nil, errors.New("ResolveEndpoint: illegal IP format")
	}
	ipaddr := &net.IPAddr{IP:ip, Zone:zone}
	if err != nil {
		return nil, err
	}
	return &Endpoint{IPAddr:ipaddr, Port:port}, nil
}

func ExtractHostAndPort(hostport string, defaultPort int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		if strings.HasSuffix(err.Error(), "missing port in address") {
			return strings.Trim(hostport, " []"), defaultPort, nil
		} else {
			return "", 0, err
		}
		
	}
	port := defaultPort
	if portStr != "" {
		port, err = net.LookupPort("ip", portStr)
		if err != nil {
			return "", 0, err
		}
	}
	return host, port, err
}

var ErrInferfaceIsDown error = errors.New("specified inferface is down")

func GetInferfaceDefaultAddr(name, network string) (ip net.Addr, err error) {
	var ipAddr *net.IPAddr
	goto Go
Error:
	return ip, err
Wrap:
	switch network {
	case "tcp": ip = &net.TCPAddr{IP:ipAddr.IP, Zone:ipAddr.Zone, }
	case "udp": ip = &net.UDPAddr{IP:ipAddr.IP, Zone:ipAddr.Zone, }
	case "ip":  ip = ipAddr
	default:err = errors.New("network of address is not a compatible type so called in dial.go"); goto Error
	}
	return
Go:
	if endpoint, err := ResolveEndpoint(name); err == nil {
		ipAddr = endpoint.IPAddr
		goto Wrap
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		goto Error
	}
	for _, ifi := range interfaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Name != name {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, addr1 := range addrs {
			switch v := addr1.(type) {
			case *net.IPAddr:
				ipAddr = v
				goto Wrap
			case *net.IPNet:
				ipAddr = &net.IPAddr{IP:v.IP}
				goto Wrap
			}
		}
	}
	err = ErrInferfaceIsDown
	goto Error
}

type DialFn func(network, address string) (net.Conn, error)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func GetDialer(network string, ifi *string, timeout time.Duration, keepAlive time.Duration) (*net.Dialer, error) {
	var addr net.Addr
	var err error
	if ifi != nil {
		if addr, err = GetInferfaceDefaultAddr(*ifi, network); err != nil {
			return nil, err
		}
	}
	return &net.Dialer{Timeout: timeout, LocalAddr:addr, KeepAlive:keepAlive, FallbackDelay:-1,}, nil
}

var ErrUnknownOptType error = errors.New("unsupported opts for Dial")

func Dial(network, address string, ifi *string, timeout time.Duration, keepAlive time.Duration, opts ...interface{}) (net.Conn, error) {
	var ctx context.Context
	for _, opt := range opts {
		switch opt := opt.(type) {
			case *TLSContext:
			if opt != nil {
				ctx = opt
			}
			default: return nil, ErrUnknownOptType
		}
	}
	if d, err := GetDialer(network, ifi, timeout, keepAlive); err == nil {
		if ctx == nil {
			return ParallelDialWithDialer(context.Background(), d, network, address, parallel_dial_total)
		}
		return ParallelDialWithDialer(ctx, d, network, address, parallel_dial_total)
	} else {
		return nil, err
	}
}

const parallel_dial_total = 2

//memory grows; await on goose's fixing
func ParallelDialWithDialer(ctx context.Context, dialer Dialer, network, addr string, races int) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	var result chan net.Conn = make(chan net.Conn)
	var done chan error = make(chan error, races)
	var p = func() {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err == nil {
			result <- conn
		}
		done <- err
	}
	for i := 0; i < races; i++ {
		go p()
	}
	var err error
	var conn net.Conn
	for i := 0; i < races; {
		select {
		case err = <- done: i++
		case c := <- result:
			if conn == nil {
				cancel()
				conn = c
			} else {
				c.Close()
				c = nil
			}
		}
	}
	close(result)
	close(done)
	if conn != nil {
		err = nil
	}
	return conn, err
}

// for DNS Packet
func ReadDP(conn net.Conn) ([]byte, error) {
	if conn == nil {
		return nil, dns.ErrConnEmpty
	}
	var err error
	var n int
	var length uint16
	var p []byte

	if _, ok := conn.(net.PacketConn); ok {
		p = make([]byte, MaxDNSUDPPacketSize)
		n, err = conn.Read(p)
		goto Ret
	}

	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	Program_dbg_full_log("[Reading - RAW packet length]: %d", length)
	if length < MinDNSPacketSize || length > MaxDNSPacketSize {
		return nil, errors.New("unexpected size of packet")
	}
	p = make([]byte, length)
	n, err = io.ReadFull(conn, p[:length])
Ret:
	Program_dbg_full_log("[Ret RAW packet length]: %d", n)
	return p[:n], err
}

// for DNS Packet
func WriteDP(conn net.Conn, p []byte, clients ...*net.Addr) error {
	Program_dbg_full_log("[Writing - RAW packet length]: %d", len(p))
	var err error
	if _, ok := conn.(net.PacketConn); ok {
		if len(p) > MaxDNSUDPPacketSize {
			
			return errors.New("Packet too large")
		}
		if len(clients) > 0 {
			_, err = conn.(net.PacketConn).WriteTo(p, *clients[0])
		} else {
			_, err = conn.Write(p)
			
		}
		return err
	}
	if len(p) > MaxDNSPacketSize {
		return errors.New("Packet too large")
	}

	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(p)))

	if _, ok := conn.(*net.TCPConn); ok {
		_, err = (&net.Buffers{l, p}).WriteTo(conn)
	} else {
		// tls,net,private method,mess up  @type buffersWriter interface -> writeBuffers(*Buffers) (int64, error)
		l = append(l, p...)
		_, err = conn.Write(l)
	}
	return err
}

/*---------------------------------------------------------------------------------------

    Others adopted from original dnscrypt-proxy (below) ww

/*--------------------------------------------------------------------------------------*/

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Min64(x, y int64) int64 {
 if x < y {
   return x
 }
 return y
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func StringQuote(str *string) string {
	str1 := strconv.QuoteToGraphic(*str)
	return str1[1 : len(str1)-1]
}