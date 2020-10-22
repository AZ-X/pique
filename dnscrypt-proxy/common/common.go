package common

import (
	"bytes"
	"container/ring"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	_ "unsafe"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	
	stamps "stammel"
)
//only if raw msg dumping
const Program_dbg_full = false

func Program_dbg_full_log(args ...interface{}) {
	if Program_dbg_full {
		format := args[0].(string)
		var params []interface{}
		if len(args) > 1 {
			params = args[1:]
			dlog.Debugf(format, params)
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
)

type RegisteredServer struct {
	Name        string
	Stamp       *stamps.ServerStamp
}

/*---------------------------------------------------------------------------------------

    Network related

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
		return nil, errors.New("ResolveEndpoint error: illegal IP format")
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
			return strings.TrimSpace(hostport), defaultPort, nil
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

func GetDialer(network string, ifi *string, Timeout time.Duration, KeepAlive time.Duration) (*net.Dialer, error) {
	var addr net.Addr
	var err error
	if ifi != nil {
		if addr, err = GetInferfaceDefaultAddr(*ifi, network); err != nil {
			return nil, err
		}
	}
	return &net.Dialer{Timeout: Timeout, LocalAddr:addr, KeepAlive:KeepAlive, FallbackDelay:-1,}, nil
}

var ErrUnknownOptType error = errors.New("unsupported opts for Dial")

func Dial(network, address string, ifi *string, Timeout time.Duration, KeepAlive time.Duration, opts ...interface{}) (net.Conn, error) {
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
	if d, err := GetDialer(network, ifi, Timeout, KeepAlive); err == nil {
		if ctx == nil {
			return d.Dial(network, address)
		}
		return d.DialContext(ctx, network, address)
	} else {
		return nil, err
	}
}

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
	if length > MaxDNSPacketSize-1 {
		return nil, errors.New("Packet too large")
	}
	if length < MinDNSPacketSize {
		return nil, errors.New("Packet too short")
	}
	p = make([]byte, length)
	n, err = io.ReadFull(conn, p[:length])
Ret:
	Program_dbg_full_log("[RAW packet length]: %d", length)
	return p[:n], err
}


func WriteDP(conn net.Conn, p []byte, clients ...*net.Addr) error {

	if _, ok := conn.(net.PacketConn); ok {
		if len(p) > MaxDNSUDPPacketSize {
			return errors.New("Packet too large")
		}
		var err error
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

	_, err := (&net.Buffers{l, p}).WriteTo(conn)
	return err
}

/*---------------------------------------------------------------------------------------

    Others

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

func StringQuote(str string) string {
	str = strconv.QuoteToGraphic(str)
	return str[1 : len(str)-1]
}

func TrimAndStripInlineComments(str string) string {
	if idx := strings.LastIndexByte(str, '#'); idx >= 0 {
		if idx == 0 || str[0] == '#' {
			return ""
		}
		if prev := str[idx-1]; prev == ' ' || prev == '\t' {
			str = str[:idx-1]
		}
	}
	return strings.TrimFunc(str, unicode.IsSpace)
}

func ReadTextFile(filename string) (string, error) {
	bin, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	bin = bytes.TrimPrefix(bin, []byte{0xef, 0xbb, 0xbf})
	return string(bin), nil
}
