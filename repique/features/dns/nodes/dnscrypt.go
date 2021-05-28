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
}

func (n *dnscryptnode) boost(o *node) interface{} {
	if o.status&status_outdated == status_outdated || n.GetDefaultExpiration().Before(time.Now()) {
		relays := n.bs_relays
		if _, err := dnscrypt.RetrieveServicesInfo(false, n.Resolver, n.dailFn, n.Network, n.ipaddr, &relays); err == nil {
			n.bs2epring(relays)
			expired := n.GetDefaultExpiration()
			return &expired
		} else {
			dlog.Debugf("dnscrypt boost failed, %v", err)
		}
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

const dnscryptmarshalfmt = "%d %d %d %d %d %x %x" + eol
func (n *dnscryptnode) marshal() *struct{c uint8; v string} { 
	s := n.GetDefaultService()
	var c strings.Builder
	fmt.Fprintf(&c, dnscryptmarshalfmt, s.Version, s.Minor, s.Serial, s.DtFrom, s.DtTo, s.MagicQuery, s.ServerPk)
	return &struct{c uint8; v string} {1,c.String()}
}

func (n *dnscryptnode) unmarshal(ss *struct{c uint8; v string}) *time.Time { 
	s := &dnscrypt.ServiceInfo{Service:&dnscrypt.Service{ServerKey:&dnscrypt.ServerKey{}}}
	c := strings.NewReader(ss.v)
	var mq, sk []byte
	if _, err := fmt.Fscanf(c, dnscryptmarshalfmt,
	&s.Version, &s.Minor, &s.Serial, &s.DtFrom, &s.DtTo, &mq, &sk); err != nil {
		panic(err)
	}
	copy(s.MagicQuery[:], mq)
	copy(s.ServerPk[:], sk)
	s.Name = n.Resolver.Name
	if s.Version == dnscrypt.XSalsa20Poly1305 {
		n.V1_Services = append(n.V1_Services, s)
	} else {
		n.V2_Services = append(n.V2_Services, s)
	}
	n.bs2epring(n.bs_relays)
	to := time.Unix(int64(s.DtTo), 0)
	return &to
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
	return dnscrypt.Query(n.dailFn, n.Network, n.GetDefaultService().Service, bin, n.ipaddr, relayAddr)
}
