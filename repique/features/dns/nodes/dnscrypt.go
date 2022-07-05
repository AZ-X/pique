package nodes

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/protocols"
	"github.com/AZ-X/pique/repique/protocols/dnscrypt"

	"github.com/jedisct1/dlog"
)

// self-bootstrap
type dnscryptnode struct {
	*protocols.NetworkBase
	*dnscrypt.Resolver
	ipaddr                  *common.Endpoint
	relayaddr               *atomic.Value //*EPRing
	dailFn                  common.DialFn
	bs_relays               []*common.Endpoint
	randomSvrPK             bool
}

const regulation_cycle = 5 * time.Second
func (n *dnscryptnode) boost(o *node) interface{} {
	relays := n.bs_relays
	if _, err := dnscrypt.RetrieveServicesInfo(false, n.Resolver, n.dailFn, n.Network, n.ipaddr, &relays); err == nil {
		n.bs2epring(relays)
		if n.randomSvrPK {
			if s := n.GetDefaultServices(); len(s) > 1 {
				expired := time.Unix(int64(s[0].DtFrom), 0).Add(time.Duration(s[0].Regular) * time.Hour).Add(regulation_cycle)
				if time.Now().Before(expired) {
					return &expired
				}
			}
		}
		expired := n.GetDefaultExpiration()
		return &expired
	} else {
		if n.randomSvrPK && time.Now().Before(n.GetDefaultExpiration()) {
			if s := n.GetDefaultService(); s != nil {
				expired := time.Unix(int64(s.DtFrom), 0).Add(time.Duration(s.Regular) * time.Hour)
				if time.Since(expired) > time.Minute {
					dlog.Debugf("abort dnscrypt early regulation boost")
					return n.GetDefaultExpiration()
				}
				return time.Now().Add(regulation_cycle)
			}
		}
		dlog.Debugf("dnscrypt boost failed, %v", err)
	}
	return nil
}

func (n *dnscryptnode) bs2epring(eps []*common.Endpoint) {
	if epring := common.LinkEPRing(eps...); epring != nil {
		epring.Do(func(v interface{}){
			dlog.Infof("relay [%s*%s]=%s", *n.Name, v.(*common.EPRing).Order(), v.(*common.EPRing).String())
		})
		n.relayaddr = &atomic.Value{}
		n.relayaddr.Store(epring)
	}
}

func (n *dnscryptnode) material() marshaling { 
	return n
}

const dnscryptmarshalfmt = "%d %d %d %d %d %d %x %x" + eol
func (n *dnscryptnode) marshal() *struct{c uint8; v string} { 
	ss := n.GetDefaultServices()
	var count uint8 = 0
	var c strings.Builder
	for _, s := range ss {
		if time.Now().After(time.Unix(int64(s.DtTo), 0)) {
			break
		}
		count++
		fmt.Fprintf(&c, dnscryptmarshalfmt, s.Version, s.Minor, s.Serial, s.DtFrom, s.DtTo, s.Regular, s.MagicQuery, s.ServerPk)
	}
	return &struct{c uint8; v string} {count, c.String()}
}

func (n *dnscryptnode) unmarshal(ss *struct{c uint8; v string}) (to *time.Time) {
	c := strings.NewReader(ss.v)
	for i := ss.c; i > 0; i -- {
		s := &dnscrypt.ServiceInfo{Service:&dnscrypt.Service{ServerKey:&dnscrypt.ServerKey{}}}
		var mq, sk []byte
		if _, err := fmt.Fscanf(c, dnscryptmarshalfmt,
		&s.Version, &s.Minor, &s.Serial, &s.DtFrom, &s.DtTo, &s.Regular, &mq, &sk); err != nil {
			panic(err)
		}
		copy(s.MagicQuery[:], mq)
		copy(s.ServerPk[:], sk)
		s.Name = n.name()
		if s.Version == dnscrypt.XSalsa20Poly1305 {
			n.V1_Services.Store(append(n.V1_Services.Load().([]*dnscrypt.ServiceInfo), s))
		} else {
			n.V2_Services.Store(append(n.V2_Services.Load().([]*dnscrypt.ServiceInfo), s))
		}
		defer func() {
			t := time.Unix(int64(s.DtTo), 0)
			if n.randomSvrPK {
				r := time.Unix(int64(s.DtFrom), 0).Add(time.Duration(s.Regular) * time.Hour)
				if time.Now().Before(r) {
					to = &r
					return
				}
			}
			to = &t
		}()
	}
	n.bs2epring(n.bs_relays)
	return
}

func (_ *dnscryptnode) proto() string {
	return DNSCrypt
}

func (n *dnscryptnode) name() *string {
	return n.Name
}

func (n *dnscryptnode) exchange(bin *[]byte, _ ...interface{}) (*[]byte, error) {
	var relayAddr *common.Endpoint
	if n.relayaddr != nil {
		ep := n.relayaddr.Load().(*common.EPRing)
		relayAddr = ep.Endpoint
		n.relayaddr.Store(ep.Next())
	}
	if n.randomSvrPK {
			return dnscrypt.Query(n.dailFn, n.Network, n.GetRandomService().Service, bin, n.ipaddr, relayAddr)
	}
	return dnscrypt.Query(n.dailFn, n.Network, n.GetDefaultService().Service, bin, n.ipaddr, relayAddr)
}
