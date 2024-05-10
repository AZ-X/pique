package nodes

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	crypto_tls "crypto/tls"
	"encoding/base64"
	"math/big"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"
	"net"
	"net/http"
	"net/url"

	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/conceptions"
	"github.com/AZ-X/pique/repique/protocols"
	"github.com/AZ-X/pique/repique/protocols/dnscrypt"
	"github.com/AZ-X/pique/repique/protocols/tls"
	"github.com/AZ-X/pique/repique/features/dns/channels"
	"github.com/AZ-X/pique/repique/features/dns/nodes/metrics"
	"github.com/AZ-X/pique/repique/services"
	stamps "github.com/AZ-X/pique/repique/unclassified/stammel"

	"github.com/jedisct1/dlog"
	"github.com/AZ-X/dns"
)


const (
	Windows  = 7
	DoH      = "DoH"
	DoT      = "DoT"
	DNSCrypt = "DNSCrypt"
)

//Predefined Well-known Tag Name
const (
	Well_Known_Tag_NO_PROXY                 = "NO-PROXY" // intranet
	Well_Known_Tag_HTTP_USE_GET             = "HTTP-USE-GET"
	Well_Known_Tag_DNS_BOOST_GROUP          = "DNS-BOOST-GROUP" // shared across all servers
	Well_Known_Tag_DNSSEC_PRIME_GROUP       = "DNSSEC-PRIME-GROUP" // shared across all servers
	Well_Known_Tag_DNSCRPT_OBTAIN_FAST_KEY  = "DNSCRPT-OBTAIN-FAST-KEY" // works with cfg:credentialpath when import_credential=false
	Well_Known_Tag_DNSCRPT_EARLY_REGULATION = "DNSCRPT-EARLY-REGULATION" // catch up 'key rotation' and use 1o2 random server PK
	Well_Known_Tag_TIMEOUT1                 = "TIMEOUT1" //1s
	Well_Known_Tag_TIMEOUT2                 = "TIMEOUT2" //2s
	Well_Known_Tag_TIMEOUT3                 = "TIMEOUT3" //3s
	Well_Known_Tag_PQENABLED                = "PQ" //tls+kyber768
	Well_Known_Tag_PQFORCED                 = "FPQ" //tls kyber768 only
)

type connectivity interface {
	boost(*node) interface{} // *uint32 or *time.Time
}

type _DNSInterface interface {
	proto() string
	exchange(*[]byte, ...interface{}) (*[]byte, error)
}

type _DNSService interface {
	connectivity
	marshalable
	_DNSInterface
}

type node_capable uint16

const (
	status_unusable  = node_capable(1 << iota) //active or inactive (subjective point of view base on metrics)
	status_broken                              //failed to assert dnssec/https/svcb; invaild pinning or insecure x509 certificate; malformed conduct of dnscrypt authentication or after no response
	status_outdated                            //invaild public key of dnscrypt or invaild ip address of bootstrapping nodes
	status_bootstrapping                       //dynamic ip address on the fly (bootstrap depends on trusted nodes has tagname: DNS-BOOST-GROUP)
	status_dnssec_lv1                          //fundamental dnssec
	status_dnssec_lv2                          //full dnssec
	status_dnssec_lv3                          //full dnssec (spare)
	status_https_svcb                          //https svcb
)

type node struct {
	_DNSService
	status node_capable
}

func (n *node) applicable() bool {
	return n.status&(
			status_unusable|
			status_outdated|
			status_broken  |
			status_bootstrapping) == 0
}

func (n *node) awaitresolution() bool {
	return n.status&(
			status_unusable|
			status_outdated|
			status_broken  |
			status_bootstrapping) == status_unusable
}

func (n *node) awaitboost() bool {
	return n.status&status_broken == 0 && n.status&(
			status_outdated|
			status_bootstrapping) != 0
}

func (n *node) dnssec() bool {
	return n.status&status_dnssec_lv1 == status_dnssec_lv1
}

func (n *node) evaluate() {
	msg := &dns.Msg{}
	msg.SetQuestion(".", dns.TypeMX)
	id := msg.Id
	dnssec := n.dnssec()
	msg.SetEdns0(uint16(common.MaxDNSUDPPacketSize), dnssec)
	opt := msg.IsEdns0()
	//https://www.iana.org/assignments/dns-sec-alg-numbers
	//8	RSA/SHA-256	RSASHA256
	//15 Ed25519	ED25519
	if dnssec {
		dau := new(dns.EDNS0_DAU)
		dau.AlgCode = append(append(dau.AlgCode, dns.RSASHA256), dns.ED25519)
		opt.Option = append(opt.Option, dau)
		
		dhu := new(dns.EDNS0_DHU)
		dhu.AlgCode = append(dhu.AlgCode, dns.SHA256)
		opt.Option = append(opt.Option, dhu)
		
		n3u := new(dns.EDNS0_N3U)
		n3u.AlgCode = append(n3u.AlgCode, dns.SHA256)
		opt.Option = append(opt.Option, n3u)
	}
	ext := new(dns.EDNS0_PADDING)
	ext.Padding = make([]byte, 32)
	opt.Option = append(opt.Option, ext)
	bin, _ := msg.Pack()
	var matchCert = func(state *crypto_tls.ConnectionState) error {
		protocol := state.NegotiatedProtocol
		if len(protocol) > 0 {
			protocol = " h protocol: " + protocol + " -"
		}
		dlog.Infof("[%s] tls%x -%s %v cipher suite: %v", *n.name(), state.Version, protocol, state.Curve, state.CipherSuite)
		for _, cert := range state.PeerCertificates {
			h1 := sha256.Sum256(cert.Raw)
			h2 := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			dlog.Debugf("fingerprint/Pin: [%s] [%s] [%x] [%s]", cert.Subject, strings.Join(cert.DNSNames, ","), h1, base64.StdEncoding.EncodeToString(h2[:]))
		}
		return nil
	}
	if outs, err := n.exchange(&bin, nil, matchCert); err == nil {
		v := &channels.Validation{} // stray one
		s := &channels.Session{}
		v.Init(nil, func(_ string) channels.Channel {return nil})
		s.RawIn = outs
		s.LastState = channels.R_OK
		v.Handle(s)
		if s.LastState == channels.V3_OK && s.Response.Id == id {
			if dnssec && !s.Response.AuthenticatedData {
				dlog.Debugf("evaluate %s: dnssec assumption is wrong", *n.name())
				return
			}
			dlog.Debugf("evaluate %s: connection is ok", *n.name())
			n.status&^=status_unusable
		} else {
			dlog.Debugf("evaluate %s:failed to unpack msg %v", *n.name(), s.LastError)
		}
	} else {
		dlog.Debugf("evaluate %s: failed to exchange; err=%v", *n.name(), err)
	}
}

type boostrunnable struct {
	n            *node
	mgr          *NodesMgr
}

func (r *boostrunnable) run() {
	dlog.Debugf("reboost %s", *r.n.name())
	r.n.status|=status_outdated
	r.mgr.fetchmaterials(r.n.name())
}

// A simple node manager across all servers
type NodesMgr struct {
	*conceptions.SemaGroup
	*materials
	*smith
	metrics.RTT
	nodes        map[string]*node
	q2nodesFunc  *[]func(*string, uint8)[]_DNSService
	groups       *[][][]_DNSService
	L2NMapping   *[]*ListenerConfiguration // mapping between listeners and nodes
	Tags         *map[string]map[string]interface{} //key:tag values:servers
	SP           func(*channels.Session)
	SPNoIPv6     *bool
	Ready        chan interface{}
}

func (mgr *NodesMgr) Init(cfg *Config, routes *AnonymizedDNSConfig, sum []byte, servers, relays, proxies map[string]*common.RegisteredServer, globalproxy *conceptions.NestedProxy, ifi *string) {
	mgr.SemaGroup = conceptions.NewSemaGroup(cfg.MaxUpstreams)
	mgr.nodes = make(map[string]*node, len(servers))
	rmappings := make(map[string][]string)
	if configRoutes := routes.Routes; configRoutes != nil {
		for _, configRoute := range configRoutes {
			rmappings[configRoute.ServerName] = configRoute.RelayNames
		}
	}
	network := "tcp"
	network2 := "udp"
	if cfg.DnscryptTCP {
		network2 = "tcp"
	}
	second := func(s int) time.Duration {
		return time.Duration(s) * time.Second
	}
	hasTagName := func(n string) bool {
		if mgr.Tags == nil {
			return false
		}
		_, found := (*mgr.Tags)[n];
		return found
	}
	hasTag := func(n1,n2 string) bool {
		if hasTagName(n1) {
			_, found := (*mgr.Tags)[n1][n2];
			return found
		}
		return false
	}
	tag2timeout := func(svr *common.RegisteredServer) *time.Duration {
		for _, t := range []struct{name string; value int}{
		{Well_Known_Tag_TIMEOUT1, 1},
		{Well_Known_Tag_TIMEOUT2, 2},
		{Well_Known_Tag_TIMEOUT3, 3},
		} {
			if hasTag(t.name, svr.Name) {
				d := second(t.value)
				return &d
			}
		}
		return nil
	}
	nbDotDohShared := &protocols.NetworkBase{IFI:ifi, Proxies:globalproxy, Network:network, Alive:second(cfg.KeepAlive), Timeout:second(cfg.Timeout),}
	nbDnscryptShared := &protocols.NetworkBase{IFI:ifi, Proxies:globalproxy, Network:network2, Alive:second(cfg.KeepAlive), Timeout:second(cfg.Timeout),}
	hasDnscrypt := false
	newProxy := func(svr *common.RegisteredServer) (proxy *conceptions.NestedProxy) {
		if hasTag(Well_Known_Tag_NO_PROXY, svr.Name) { // first place; ignore any proxy referred
			return conceptions.InitProxies()
		}
		par := strings.Split(svr.Stamp.Proxies, common.Delimiter)
		if len(par) == 0 || len(par[0]) == 0 {
			return
		}
		proxy = conceptions.InitProxies()
		for _, name := range par {
			if p, found := proxies[name]; found {
				if uri, err := url.Parse(p.Stamp.ProviderName); err == nil {
					var ep *common.Endpoint
					if len(p.Stamp.ServerAddrStr) > 0 {
						if ep, err = common.ResolveEndpoint(p.Stamp.ServerAddrStr); err !=nil {
							panic("failed to parse ip-port of proxy -> " + p.Stamp.ServerAddrStr)
						}
					}
					proxy.AddProxy(uri, ep)
				}
				panic("failed to parse the proxy URL " + p.Stamp.ProviderName)
			}
			panic("proxy stamp not found -> " + name )
		}
		return
	}
	newNetworkBase := func(svr *common.RegisteredServer, d *protocols.NetworkBase) *protocols.NetworkBase {
		if p, t := newProxy(svr), tag2timeout(svr); p == nil && t == nil {
			return d
		} else {
			if t == nil {
				t = &d.Timeout
			}
			return &protocols.NetworkBase{IFI:d.IFI, Proxies:d.Proxies.Merge(p), Network:d.Network, Alive:d.Alive, Timeout:*t,}
		}
	}
	newTLSNode := func(svr *common.RegisteredServer) (node *tlsnode) {
		pq := tls.NPQ
		if hasTag(Well_Known_Tag_PQENABLED, svr.Name) {
			pq = tls.PQ
		} else if hasTag(Well_Known_Tag_PQFORCED, svr.Name) {
			pq = tls.FPQ
		}
		return &tlsnode{TLSMeta:tls.NewTLSMeta(svr, newNetworkBase(svr, nbDotDohShared), cfg.TLSDisableSessionTickets, pq)}
	}
	var trans *http.Transport
	newDoHNode := func(svr *common.RegisteredServer) (node *dohnode) {
		if trans == nil {
			trans = tls.NewZTransport(nbDotDohShared.Alive, nbDotDohShared.Timeout)
		}
		path := svr.Stamp.Path
		method := tls.POST
		if hasTag(Well_Known_Tag_HTTP_USE_GET, svr.Name) {
			method = tls.GET
		}
		return &dohnode{tlsnode:newTLSNode(svr), trans:trans, path:&path, method:method,}
	}
	inittls13 := false
	newDoTDoHNode := func(svr *common.RegisteredServer) (node _DNSService, c node_capable) {
		if !inittls13 {
			tls.InitTLS13()
			inittls13 = true
		}
		doh := svr.Stamp.Proto.String() == "DoH"
		if doh {
			node = newDoHNode(svr)
		} else {
			node = newTLSNode(svr)
		}
		if len(svr.Stamp.ServerAddrStr) == 0 {
			if !cfg.Bootstrap || !hasTagName(Well_Known_Tag_DNS_BOOST_GROUP) {
				panic("enable bootstrap and ensure Well_Known_Tag_DNS_BOOST_GROUP for -> " + svr.Name)
			}
			if doh {
				node.(*dohnode).connectivity = mgr
				node = &doh_bs_node{dohnode:node.(*dohnode), tls_bs_ips:&tls_bs_ips{n:node.(*dohnode).tlsnode, port:443},}
			} else {
				node.(*tlsnode).connectivity = mgr
				node = &tls_bs_node{tlsnode:node.(*tlsnode), tls_bs_ips:&tls_bs_ips{n:node.(*tlsnode), port:853,},}
			}
			c = status_bootstrapping|status_outdated
		}
		if cfg.DefaultUnavailable {
			c|=status_unusable
		}
		return
	}
	inforoutestar := false
	relayall, hasroutestar := rmappings[common.STAR]
	//only support relay stamp; convert dnscrypt stamp to relay stamp via WPF-GO-dnscrypt-proxy-md
	newroutes := func(name string) (rs []*common.Endpoint) {
		if hasroutestar && !inforoutestar {
			dlog.Infof("dnscrypt repeater: routing everything via %v", relayall)
			inforoutestar = true
		}
		rs = make([]*common.Endpoint, 0)
		if len(rmappings) != 0 {
			relayNames, found := rmappings[name]
			if !found && hasroutestar {
				relayNames = relayall
			}
			appendto := func(rname string, r *common.RegisteredServer) {
				if rep, err := common.ResolveEndpoint(r.Stamp.ServerAddrStr); err == nil {
					dlog.Infof("dnscrypt repeater: routing [%s] via [%s] addr=>%s", name, rname, rep.String())
					rs = append(rs, rep)
				} else {
					panic(err.Error() + ", unsupported ip address for " + name)
				}
			}
			if len(relayNames) > 0 {
				dlog.Infof("select relays for %s", name)
				if relayNames[0] == common.STAR {
					for rname, r := range relays {
						appendto(rname, r)
					}
					return
				}
				for _, rname := range relayNames {
					if r, found := relays[rname]; found {
						appendto(rname, r)
					}
				}
			}
		}
		return
	}
	newDnscryptNode := func(svr *common.RegisteredServer) (node *dnscryptnode, c node_capable) {
		hasDnscrypt = true
		c = status_outdated
		if cfg.DefaultUnavailable {
			c|=status_unusable
		}
		name := svr.Name
		if len(svr.Stamp.ServerPk) != ed25519.PublicKeySize {
			panic(dlog.Errorf("unsupported public key for %s key=%v", name, svr.Stamp.ServerPk))
		}
		var pk ed25519.PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(pk, svr.Stamp.ServerPk)
		r := &dnscrypt.Resolver{
			Name:&name,
			Identifiers:strings.Split(svr.Stamp.ProviderName, common.Delimiter),
			PublicKey: pk,
			V1_Services: &atomic.Value{},
			V2_Services: &atomic.Value{},
			VN_Services: &atomic.Value{},
		}
		r.V1_Services.Store(make([]*dnscrypt.ServiceInfo, 0))
		r.V2_Services.Store(make([]*dnscrypt.ServiceInfo, 0))
		r.VN_Services.Store(make([]*dnscrypt.ServiceInfo, 0))
		ep, err := common.ResolveEndpoint(svr.Stamp.ServerAddrStr)
		if err != nil {
			panic(err.Error() + ", unsupported ip address for " + name)
		}
		node = &dnscryptnode{
			NetworkBase:newNetworkBase(svr, nbDnscryptShared),
			Resolver:r,
			ipaddr:ep,
			bs_relays:newroutes(name),
			randomSvrPK:hasTag(Well_Known_Tag_DNSCRPT_EARLY_REGULATION, svr.Name),
		}
		node.dailFn = func(network, address string) (net.Conn, error) {
			if network == "udp" && !node.Proxies.UDPProxies() {
				network = "tcp"
			}
			var pc net.Conn
			var err error
			if !node.Proxies.HasValue() {
				pc, err = common.Dial(network, address, node.IFI, node.Timeout, -1)
			} else {
				pc, err = node.Proxies.GetDialContext()(nil, node.IFI, network, address)
			}
			if err == nil {
				err = pc.SetDeadline(time.Now().Add(node.Timeout))
			}
			return pc, err
		}
		return
	}
	var names []string
	for _, svr := range servers {
		node := &node{}
		switch svr.Stamp.Proto.String() {
			case "DoH", "DoT": node._DNSService, node.status = newDoTDoHNode(svr)
			case "DNSCrypt": node._DNSService, node.status = newDnscryptNode(svr)
		}
		if svr.Stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0 {
			node.status|=status_dnssec_lv1
		}
		mgr.nodes[*node.name()] = node
		names = append(names, *node.name())
	}
	mgr.RTT = metrics.NewRTT(names, Windows, cfg.NoMetrics)
	if hasDnscrypt {
		dlog.Noticef("dnscrypt-protocol bind to %s", network2)
	}
	mgr.smith = &smith{}
	if len(cfg.ExportCredentialPath) > 0 {
		mgr.materials = &materials{}
		mgr.open(cfg.ExportCredentialPath, sum)
		dnscrpt_obtain_fast_key := hasTagName(Well_Known_Tag_DNSCRPT_OBTAIN_FAST_KEY)
		if cfg.ImportCredential || dnscrpt_obtain_fast_key {
			var nodes []marshalable
			for _, n := range mgr.nodes {
				if cfg.ImportCredential || hasTag(Well_Known_Tag_DNSCRPT_OBTAIN_FAST_KEY, *n.name()) {
					nodes = append(nodes, n)
				}
			}
			updates, dts := mgr.unmarshalto(nodes)
			for i, n := range updates {
				dlog.Debugf("exported material to %s", *n.name())
				node := n.(*node)
				node.status&^=status_outdated|status_bootstrapping
				f := func(){
					node.status|=status_outdated
				}
				if cfg.FetchInterval > 0 {
					r := &boostrunnable{node, mgr,}
					f = r.run
				}
				if dt := dts[i]; dt != nil {
					dlog.Debugf("next expiration for %s on %v", *n.name(), dt)
					mgr.addevent(dt, 0, f)
				} else if cfg.FetchInterval > 0 {
					mgr.addevent(nil, uint32(cfg.FetchInterval)*60 - 5, f)
				}
			}
		}
	}
	if len(mgr.nodes) > 0 && cfg.FetchInterval > 0 {
		mgr.Ready = make(chan interface{})
		go func(interval time.Duration, least2 bool) {
			<-mgr.Ready
			close(mgr.Ready)
			var f func()
			f = func () {
				mgr.fetchmaterials()
				delay := interval
				lives, total := mgr.available()
				if least2 && lives <= 1 && total != lives {
						delay = time.Duration(total - lives) *  time.Second
				} else {
					debug.FreeOSMemory()
				}
				mgr.addevent(nil, uint32(delay.Seconds()), f)
			}
			f()
			mgr.pilot()
		}(time.Duration(max(60, cfg.FetchInterval)) * time.Minute, cfg.FetchAtLeastTwo)
	}
}

func (mgr *NodesMgr) available() (c int, t int) {
	for _,node := range mgr.nodes {
		t++
		if node.applicable() {
			c++
		}
	}
	dlog.Debugf("lives %d, total %d", c, t)
	return
}

const _DNSRoot = "."
var svrName = channels.NonSvrName
// booster for DoH & DoT
func (mgr *NodesMgr) boost(n *node) interface{} {
	var node *tlsnode
	var bs_ips *tls_bs_ips
	switch n.proto() {
		case DoH:
			node = n._DNSService.(*doh_bs_node).dohnode.tlsnode
			bs_ips = n._DNSService.(*doh_bs_node).tls_bs_ips
		case DoT:
			node = n._DNSService.(*tls_bs_node).tlsnode
			bs_ips = n._DNSService.(*tls_bs_node).tls_bs_ips
	}
	
	s := &channels.Session{LastState:channels.V1_OK, ServerName:&svrName}
	s.Request = &dns.Msg{}
	t := dns.TypeA
	if mgr.SPNoIPv6 != nil && !*mgr.SPNoIPv6 {
		t = dns.TypeAAAA
	}
	s.Request.SetQuestion(node.DomainName + _DNSRoot, t)
	s.Request.Id = 0
	s.Question = &s.Request.Question[0]
	mgr.SP(s) //SPGroup=Listener=0
	if s.LastError != nil {
		return nil
	}
	if bs_ips.ips == nil {
		bs_ips.ips = make(map[[16]byte]interface{})
	}
	var ttl *uint32
	const min_ttl_boost uint32 = 60 * 60 // an hour
	var endpoints []*common.Endpoint
	for i := len(s.Response.Answer); i > 0; i-- {
		rr := s.Response.Answer[i-1]
		if rr.Header().Rrtype == t {
			var ip net.IP
			switch rr.Header().Rrtype {
				case dns.TypeA:    ip = rr.(*dns.A).A.To16()
				case dns.TypeAAAA: ip = rr.(*dns.AAAA).AAAA
			}
			if !ip.IsGlobalUnicast() {
				continue
			}
			if ttl == nil || *ttl < rr.Header().Ttl {
				ttl = &rr.Header().Ttl
			}
			if *ttl < min_ttl_boost {
				*ttl = min_ttl_boost
			}
			var key [16]byte
			copy(key[:], ip)
			bs_ips.ips[key] = nil
			ep := &common.Endpoint{IPAddr:&net.IPAddr{IP:ip}, Port:bs_ips.port}
			endpoints = append(endpoints, ep)
		}
	}
	if len(endpoints) == 0 {
		return nil
	}
	if len(bs_ips.ips) == 1 {
		node.IPs.Store(endpoints[0].String())
	} else if len(bs_ips.ips) > 1 {
		epring := common.LinkEPRing(endpoints...)
		node.IPs.Store(epring)
	}
	return ttl
}

func (mgr *NodesMgr) fetchmaterials(opts  ...*string) {
	if len(opts) == 0 {
		if !mgr.BeginExclusive() {
			dlog.Warn("semi-refresh occurs")
			return
		}
		mgr.proveResolution()
		mgr.associate()
		mgr.EndExclusive()
	}

	nodes, rts := make([]*node, 0), make([]chan interface{}, 0)
	for key, n := range mgr.nodes {
		if (len(opts) == 0 || key == *opts[0]) && n.awaitboost() {
			nodes = append(nodes, n)
			rt := make(chan interface{})
			rts = append(rts, rt)
			go func(n1 *node, r chan<- interface{}) {
				dlog.Debugf("ready to boost %s", *n1.name())
				r <- n1.boost(n1)
				close(r)
			}(n, rt)
		}
	}
	updates := make([]*node, 0)
	for c := len(rts) -1; c >= 0; c-- {
		rt := <- rts[c]
		if rt != nil {
			updates = append(updates, nodes[c])
			r := &boostrunnable{nodes[c], mgr,}
			if dt, ok := rt.(*time.Time); ok {
				mgr.addevent(dt, 0, r.run)
			} else {
				mgr.addevent(nil, *rt.(*uint32) + uint32(c), r.run)
			}
		} else {
			dlog.Debugf("can not boost %s", *nodes[c].name())
		}
	}

	if !mgr.BeginExclusive() {
		dlog.Warn("semi-refresh occurs")
		return
	}
	defer mgr.EndExclusive()
	var dirty bool
	for _, node := range updates {
		if mgr.materials != nil {
			if mgr.marshalfrom(node) {
				dlog.Debugf("unchanged material of %s", *node.name())
			} else {
				dirty = true
			}
		}
		dlog.Debugf("%s has been boosted", *node.name())
		node.status&^=status_outdated|status_bootstrapping
	}
	if dirty {
		if mgr.materials != nil {
			mgr.savepoint()
		}
	}
	if len(opts) == 0 {
		mgr.proveResolution()
	}
	mgr.associate()
}

//provision
func (mgr *NodesMgr) proveResolution() {
	nodes :=  make([]*node, 0)
	for _, n := range mgr.nodes {
		if n.awaitresolution() {
			nodes = append(nodes, n)
		}
	}
	done := make(chan interface{}, len(nodes))
	for _, n := range nodes {
		go func(n1 *node, d chan<- interface{}) {
			n1.evaluate()
			d <- nil
		}(n, done)
	}
	for c := len(nodes) - 1; c >= 0; c-- {
		<- done
	}
	close(done)
}

//lots of mappings
func (mgr *NodesMgr) associate() {
	if mgr.L2NMapping == nil {
		groups := make([][][]_DNSService, 1)
		groups[0] = make([][]_DNSService, 1)
		for _, node := range mgr.nodes {
			if node.applicable() {
				groups[0][0] = append(groups[0][0], node._DNSService)
			}
		}
		mgr.groups = &groups
		return
	}
	length := len(*mgr.L2NMapping)
	groups := make([][][]_DNSService, length)
	q2nodesFunc := make([]func(*string, uint8)[]_DNSService, length)
	wellknowntags := func(svrs [][]_DNSService, tags ...string) {
		for idx, tag := range tags {
			servers := make([]_DNSService, 0)
			if bgroup, found := (*mgr.Tags)[tag]; found {
				for name, _ := range bgroup {
					if node := mgr.nodes[name]; node.applicable() {
						servers = append(servers, node._DNSService)
					}
				}
			}
			svrs[idx] = servers
		}
	}
	for i, lcp := range *mgr.L2NMapping {
		idx := i //capture range variable
		lc := lcp //capture range variable
		if lc == nil && idx != 0 {
			continue
		}
		var svrs [][]_DNSService
		if lc != nil && lc.Regex != nil {
			svrs = make([][]_DNSService, lc.Regex.NumSubexp() + 1)
			for name, group := range *lc.Groups {
				servers := make([]_DNSService, 0)
				for _, name := range group.Servers {
					if node := mgr.nodes[*name]; node.applicable() {
						servers = append(servers, node._DNSService)
					}
				}
				svrs[lc.Regex.SubexpIndex(name)] = servers
			}
			f := func(qName *string, _ uint8)[]_DNSService {
				idxes := lc.Regex.FindStringSubmatchIndex(*qName)
				if idxes == nil {
					return nil
				}
				//union all operation
				l := 0
				for k, v := range (*mgr.groups)[idx] {
					if v != nil && idxes[2*k] != -1 { //[2*n:2*n+1]
						l += len(v)
					}
				}
				ret := make([]_DNSService, l)
				pos := 0
				for k, v := range (*mgr.groups)[idx] {
					if v != nil && idxes[2*k] != -1 {
						copy(ret[pos:], v)
						pos += len(v)
					}
				}
				return ret
			}
			q2nodesFunc[idx] = f
		} else {
			svrs = make([][]_DNSService, 1)
			servers := make([]_DNSService, 0)
			if idx != 0 {
				for _, name := range lc.ServerList.Servers {
					if node := mgr.nodes[*name]; node.applicable() {
						servers = append(servers, node._DNSService)
					}
				}
				svrs[0] = servers
			} else {
				svrs = make([][]_DNSService, 2)
				if mgr.Tags != nil {
					wellknowntags(svrs, Well_Known_Tag_DNS_BOOST_GROUP, Well_Known_Tag_DNSSEC_PRIME_GROUP)
				}
			}
			f := func(qName *string, spgroup uint8)[]_DNSService {
				if idx != 0 {
					return (*mgr.groups)[idx][0]
				}
				return (*mgr.groups)[0][spgroup]
			}
			q2nodesFunc[idx] = f
		}
		groups[idx] = svrs
	}
	mgr.q2nodesFunc = &q2nodesFunc
	mgr.groups = &groups
}

func (mgr *NodesMgr) pick(s *channels.Session) _DNSService {
	if s.ServerName != nil && *s.ServerName != channels.NonSvrName {
		return mgr.nodes[*s.ServerName]._DNSService
	}

	var candidates []_DNSService
	if mgr.q2nodesFunc != nil {
		if f := (*mgr.q2nodesFunc)[s.Listener]; f != nil {
			candidates = f(&s.Name, s.SPGroup)
		}
	} else {
		candidates = (*mgr.groups)[0][0]
	}

	cc := len(candidates)
	if cc == 1 {
		return candidates[0]
	}
	if cc <= 0 {
		return nil
	}
	b := new(big.Int).SetInt64(int64(cc))
	br, _ := rand.Int(rand.Reader, b)
	random_idx := int(br.Int64())
	return candidates[random_idx]
}

func (mgr *NodesMgr) Query(s *channels.Session) error {
	return mgr.query(s, nil)
}

func (mgr *NodesMgr) query(s *channels.Session, cbs ...interface{}) error {
goto Go
IntFault:
	return channels.Error_Stub_Internal
SvrFault:
	return channels.Error_Stub_SvrFault
Timeout:
	return channels.Error_Stub_Timeout
Go:
	switch mgr.Acquire(false) {
		case conceptions.ErrSemaBoundary:
			dlog.Warnf("too many remote resolving; goroutines:%d", runtime.NumGoroutine())
			goto IntFault
		case conceptions.ErrSemaExcEntry:
			dlog.Warn("mute remote resolvers while refreshing")
			goto IntFault
	}
	defer mgr.Release()
	service := mgr.pick(s)
	if service == nil {
		goto IntFault
	}
	s.ServerName = service.name()
	dlog.Debugf("ID: %5d I: |%-25s| [%s] %dms | %d", s.ID, s.Name, *s.ServerName, int(mgr.RTT.Avg(*s.ServerName)), runtime.NumGoroutine())

	timer := time.Now()
	if service.proto() == DNSCrypt {
		node := service.(*dnscryptnode)
		if node.relayaddr!= nil {
			name := common.STAR + node.relayaddr.Load().(*common.EPRing).Order()
			s.ExtraServerName = &name
		}
	}
	var err error
	s.RawIn, err = service.exchange(s.RawOut, cbs...)
	if err != nil {
		switch err := err.(type) {
		case interface {Timeout() bool}:
			if err.Timeout() {
				dlog.Debugf("%v [%s]", err, *service.name())
				goto Timeout
			}
		}
		errd := err
Unwrap2SyscallError:
		switch errt := errd.(type) {
		case interface {Unwrap() error}:
			switch interr := errt.Unwrap().(type) {
				case *os.SyscallError:
				if interr.Syscall == "bind" || 
				(interr.Syscall == "connect" && 
				interr.Err != nil && 
				interr.Err.Error() == "no route to host") {
					dlog.Warnf("%v [%s]", err, *service.name())
					goto IntFault
				}
				default:
					if errd != interr {
						errd = interr
						goto Unwrap2SyscallError
					}
			}
		}
		dlog.Errorf("%v [%s]", err, *service.name())
		goto SvrFault
	}
	elapsed := time.Since(timer).Nanoseconds() / 1000000
	mgr.RTT.Add(*service.name(), float64(elapsed))
	return nil
}

type ListenerConfiguration struct {
	Regex                         *services.Regexp_builder
	Groups                        *map[string]*Servers
	ServerList                    *Servers
	DNSSEC                        bool
}

type Servers struct {
	Priority                      bool
	DNSSEC                        bool
	Servers                       []*string
}

type Config struct {
	ServerNames              []string    `toml:"enabled_server_names"` // temporary filter of names
	DisabledServerNames      []string    `toml:"disabled_server_names"` // temporary filter of names
	DnscryptTCP              bool        `toml:"dnscrypt_use_tcp"` // parameter for dnscrypt protocol
	Bootstrap                bool        `toml:"bootstrap"` // allow bootstrap; no ip address
	TLSDisableSessionTickets bool        `toml:"tls_disable_session_tickets"` // parameter for (doh/dot)tls protocol
	Timeout                  int         `toml:"timeout"` // parameter for communication protocol
	KeepAlive                int         `toml:"keepalive"` // parameter for communication protocol
	MaxUpstreams             uint32      `toml:"max_concurrent_upstreams"` // simultaneous outgoing dns query directly by downstreams
	ExportCredentialPath     string      `toml:"credentialpath"` // export persistence credential file
	ImportCredential         bool        `toml:"import_credential"` // load persistence credential file when startup and skip seeking public key(dnscrypt) if valid till now
	FetchInterval            int         `toml:"interval"` // to fetch public key of dnscrypt or determine connectivity to the upstreams; 0>=no_interval
	DefaultUnavailable       bool        `toml:"default_unavailable"` // mark all nodes unavailable on startup then determine connectivity for each
	FetchAtLeastTwo          bool        `toml:"at_least_one_or_two"` // keep fetching without interval until one(n=1) or two(n>1) nodes are available
	NoMetrics                bool        `toml:"no_metrics"` // lock free; useful at low hardware conditions
}

type SourceConfig struct {
	URL                      string      //faker for fun
	URLs                     []string    //faker for fun
	Prefix                   string      //of names
	MinisignKeyStr           string      `toml:"minisign_key"`
	CacheFile                string      `toml:"cache_file"`
	FormatStr                string      `toml:"format"` //dummy of creation
	RefreshDelay             int         `toml:"refresh_delay"` //faker for fun
}

type AnonymizedDNSRouteConfig struct {
	ServerName string   `toml:"server_name"`
	RelayNames []string `toml:"via"`
}

type AnonymizedDNSConfig struct {
	Routes []AnonymizedDNSRouteConfig `toml:"routes"`
}
