package main

import (
	"bytes"
	"container/ring"
	"context"
	"errors"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	_ "unsafe"

	"github.com/miekg/dns"
)
//only if raw msg dumping
const program_dbg_full = false

const (
	ClientMagicLen          = 8
	MaxHTTPBodyLength       = 4000000
	MinDNSPacketSize        = 12 + 5
	MaxDNSPacketSize        = dns.MaxMsgSize
	MaxDNSUDPPacketSize     = dns.DefaultMsgSize
	MaxDNSUDPSafePacketSize = 1252
)

/*---------------------------------------------------------------------------------------

    Network related

/*--------------------------------------------------------------------------------------*/

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
			return d.Dial(network, address)
		}
		return d.DialContext(ctx, network, address)
	} else {
		return nil, err
	}
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
