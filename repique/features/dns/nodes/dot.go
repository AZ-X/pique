package nodes

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/protocols/tls"

	"github.com/jedisct1/dlog"
)

type tlsnode struct {
	connectivity
	*tls.TLSMeta
}

func (n *tlsnode) material() marshaling { 
	return nil
}

func (_ *tlsnode) proto() string {
	return DoT
}

func (n *tlsnode) name() *string {
	return n.Name
}

func (n *tlsnode) exchange(blob *[]byte, args ...interface{}) (*[]byte, error) {
	var ctx context.Context
	if len(args) > 0 {
		if args[0] != nil {
			ctx = args[0].(context.Context)
		}
	}
	var cbs []interface{}
	if len(args) > 1 {
		cbs = append(cbs, args[1])
	}
	return n.FetchDoT(n.Network, ctx, blob, 0, cbs...)
}

const ipsmarshalfmt = "%v" + eol
type tls_bs_ips struct {
	n               *tlsnode
	port            int
	ips             map[[16]byte]interface{}
}

func (bs *tls_bs_ips) marshal() *struct{c uint8; v string} {
	var c strings.Builder
	var count uint8 = 0
	for ipb, _ := range bs.ips {
		var ip net.IP = ipb[:]
		fmt.Fprintf(&c, ipsmarshalfmt, ip)
		count++
	}
	return &struct{c uint8; v string} {count,c.String()}
}

func (bs *tls_bs_ips) unmarshal(s *struct{c uint8; v string}) *time.Time {
	bs.ips = make(map[[16]byte]interface{}, s.c)
	c := strings.NewReader(s.v)
	var endpoints []*common.Endpoint
	for i := s.c; i > 0; i-- {
		var ipb [16]byte
		var ip net.IP
		fmt.Fscanf(c, ipsmarshalfmt, &ip)
		if err := ip.UnmarshalText(ip); err != nil {
			dlog.Debugf("wrong ip format for %s, err=%v", *bs.n.name(), err)
		}
		copy(ipb[:], ip.To16())
		bs.ips[ipb] = nil
		dlog.Debugf("loading ip material %s for %s", ip, *bs.n.name())
		ep := &common.Endpoint{IPAddr:&net.IPAddr{IP:ip}, Port:bs.port}
		endpoints = append(endpoints, ep)
	}
	if s.c > 1 {
		epring := common.LinkEPRing(endpoints...)
		bs.n.IPs = &atomic.Value{}
		bs.n.IPs.(*atomic.Value).Store(epring)
	} else {
		bs.n.IPs = endpoints[0].String()
	}
	return nil
}

// bootstrap
type tls_bs_node struct {
	*tlsnode
	*tls_bs_ips
}

func (n *tls_bs_node) material() marshaling { 
	return n.tls_bs_ips
}
