package main

import (
	"bytes"
	"container/ring"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"unicode"
	
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

var (
	FileDescriptors   = make([]*os.File, 0)
	FileDescriptorNum = 0
)

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

func MinF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func MaxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func StringReverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func StringTwoFields(str string) (string, string, bool) {
	if len(str) < 3 {
		return "", "", false
	}
	pos := strings.IndexFunc(str, unicode.IsSpace)
	if pos == -1 {
		return "", "", false
	}
	a, b := strings.TrimFunc(str[:pos], unicode.IsSpace), strings.TrimFunc(str[pos+1:], unicode.IsSpace)
	if len(a) == 0 || len(b) == 0 {
		return a, b, false
	}
	return a, b, true
}

func StringQuote(str string) string {
	str = strconv.QuoteToGraphic(str)
	return str[1 : len(str)-1]
}

func StringStripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
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

func ResolveEndpoint(hostport string) (*Endpoint, error) {
	host, port, err := ExtractHostAndPort(hostport, 0)
	if err != nil {
		return nil, err
	}
	ipaddr, err := net.ResolveIPAddr("ip", host)
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

func ReadTextFile(filename string) (string, error) {
	bin, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	bin = bytes.TrimPrefix(bin, []byte{0xef, 0xbb, 0xbf})
	return string(bin), nil
}
