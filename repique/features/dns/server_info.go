package dns

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	
	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/conceptions"
	"github.com/AZ-X/pique/repique/features/dns/channels"
	"github.com/AZ-X/pique/repique/protocols/dnscrypt"
	"github.com/jedisct1/dlog"
	mm "github.com/RobinUS2/golang-moving-average"
	stamps "github.com/AZ-X/pique/repique/unclassified/stammel"
	"github.com/AZ-X/dns"
)

const Windows = 7


type ServerInterface interface {
	Proto()         string
	Query(*Proxy, *[]byte, ...interface{}) (*[]byte, error)
}

type DNSCryptInfo struct {
	*dnscrypt.Resolver
	*ServerInfo
	Proxies            *conceptions.NestedProxy  // individual proxies chain
	IPAddr             *atomic.Value //*EPRing
	RelayAddr          *atomic.Value //*EPRing
}

func (info *DNSCryptInfo) Proto() string {
	return "DNSCrypt"
}

func (info *DNSCryptInfo) Query(p *Proxy, r *[]byte, args ...interface{}) (*[]byte, error) {
	return p.ExchangeDnScRypt(info, r)
}

type DOHInfo struct {
	*ServerInfo
	Path           	   string
	useGet             bool
}

func (info *DOHInfo) Proto() string {
	return "DoH"
}

func (info *DOHInfo) Query(p *Proxy, r *[]byte, args ...interface{}) (*[]byte, error) {
	return p.DoHQuery(info.Name, info, nil, r)
}

type DOTInfo struct {
	*ServerInfo
}

func (info *DOTInfo) Proto() string {
	return "DoT"
}

func (info *DOTInfo) Query(p *Proxy, r *[]byte, args ...interface{}) (*[]byte, error) {
	return p.DoTQuery(info.Name, nil, r)
}

type ServerInfo struct {
	Name               string
	Info               ServerInterface
	Timeout            time.Duration
	rtt                *mm.ConcurrentMovingAverage
}

type Occurrence int

const (
	OccurrenceNone = Occurrence(iota)
	OccurrenceLeading
	OccurrenceRandom
)


type ServersInfo struct {
	inner             []*ServerInfo
	innerFuncs        *map[int]func(qName *string)[]*ServerInfo
	innerGroups       *map[int]map[int][]*ServerInfo
	RegisteredServers []common.RegisteredServer
	Occurrence
}

func NewServersInfo() *ServersInfo {
	return &ServersInfo{RegisteredServers: make([]common.RegisteredServer, 0)}
}

func (serversInfo *ServersInfo) registerServer(name string, stamp *stamps.ServerStamp) {
	newRegisteredServer := common.RegisteredServer{Name: name, Stamp: stamp}
	for i, oldRegisteredServer := range serversInfo.RegisteredServers {
		if oldRegisteredServer.Name == name {
			serversInfo.RegisteredServers[i] = newRegisteredServer
			return
		}
	}
	serversInfo.RegisteredServers = append(serversInfo.RegisteredServers, newRegisteredServer)
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) (int, error) {
	dlog.Notice("refreshing certificates")
	proxy.Cancel()
	proxy.Ctx, proxy.Cancel = context.WithCancel(context.Background())
	if !proxy.SmaxClients.BeginExclusive() {
		return 0, errors.New("semi-refresh occurs")
	}
	defer proxy.SmaxClients.EndExclusive()
	RegisteredServers := serversInfo.RegisteredServers
	liveServers := 0
	var err error
	var frs = make(map[common.RegisteredServer]func(common.RegisteredServer), 0)
	var total = len(RegisteredServers) - len(serversInfo.inner)
	var rts = make(chan *ServerInfo, total)
RowLoop:
	for _, reg := range RegisteredServers {
		for _, server := range serversInfo.inner {
			if server.Name == reg.Name {
				liveServers++
				continue RowLoop
			}
		}
		frs[reg] = func(reg common.RegisteredServer) {
			info, err := fetchServerInfo(proxy, reg.Name, reg.Stamp, true)
			if err != nil {
				dlog.Debug(err)
				rts <- nil
			} else {
				rts <- &info
			}
		}
	}
	for r, f := range frs {
		go f(r)
	}
	for c := 0; c != total; c++ {
		select {
			case rt := <- rts:
			if rt != nil {
				serversInfo.inner = append(serversInfo.inner, rt)
				liveServers++
			}
		}
	}
	sort.SliceStable(serversInfo.inner, func(i, j int) bool {
		return serversInfo.inner[i].rtt.Avg() < serversInfo.inner[j].rtt.Avg()
	})
	if(liveServers > 0) {
		inner := serversInfo.inner
		if proxy.ListenerCfg != nil {
			inners := make(map[int]map[int][]*ServerInfo)
			innerfs := make(map[int]func(qName *string)[]*ServerInfo)
			for idx, lc := range *proxy.ListenerCfg {
				svrs := make(map[int][]*ServerInfo)
				if lc.Regex != nil {
					for name, group := range *lc.Groups {
						servers := make([]*ServerInfo, 0)
						for _, server := range serversInfo.inner {
							for _, name := range group.Servers {
								if *name == server.Name {
									servers = append(servers, server)
								}
							}
						}
						svrs[lc.Regex.SubexpIndex(name)] = servers
					}
					f := func(qName *string)[]*ServerInfo {
						idxes := lc.Regex.FindStringSubmatchIndex(*qName)
						if idxes == nil {
							return nil
						}
						//union all operation
						l := 0
						for k, v := range (*serversInfo.innerGroups)[idx] {
							if idxes[2*k] != -1 { //[2*n:2*n+1]
								l += len(v)
							}
						}
						ret := make([]*ServerInfo, l)
						pos := 0
						for k, v := range (*serversInfo.innerGroups)[idx] {
							if idxes[2*k] != -1 {
								copy(ret[pos:], v)
								pos += len(v)
							}
						}
						return ret
					}
					innerfs[idx] = f
				} else {
					servers := make([]*ServerInfo, 0)
					for _, server := range serversInfo.inner {
						for _, name := range lc.ServerList.Servers {
							if *name == server.Name {
								servers = append(servers, server)
							}
						}
					}
					svrs[0] = servers
					f := func(qName *string)[]*ServerInfo {
						return (*serversInfo.innerGroups)[idx][0]
					}
					innerfs[idx] = f
				}
				inners[idx] = svrs
			}
			serversInfo.innerFuncs = &innerfs
			serversInfo.innerGroups = &inners
		}
		if len(inner) > 1 {
			dlog.Notice("sorted latencies:")
			for _, server := range inner {
				dlog.Noticef("- %5.fms %s", server.rtt.Avg(), server.Name)
			}
		}
		dlog.Noticef("serve with the lowest initial latency: %s (rtt: %.fms)", inner[0].Name, inner[0].rtt.Avg())
	}
	return liveServers, err
}


func (serversInfo *ServersInfo) getOne(s *channels.Session) *ServerInfo {
	var servers = serversInfo.inner
	if serversInfo.innerFuncs != nil {
		if f, ok := (*serversInfo.innerFuncs)[s.Listener]; ok {
			servers = f(&s.Name)
		}
	}
	serversCount := len(servers)
	if serversCount <= 0 {
		return nil
	}
	if s.ServerName != nil && *s.ServerName != channels.NonSvrName {
		for _, svr := range servers {
			if svr.Name == *s.ServerName {
				return svr
			}
		}
		return nil
	}
	var candidate int
	switch serversInfo.Occurrence {
	case OccurrenceLeading:
		candidate = 0
	default:
		candidate = rand.Intn(serversCount)
	}
	serverInfo := servers[candidate]
	dlog.Debugf("ID: %5d I: |%-25s| [%s] %dms", s.ID, s.Name, serverInfo.Name, int(serverInfo.rtt.Avg()))
	return serverInfo
}

func fetchServerInfo(proxy *Proxy, name string, stamp *stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	switch stamp.Proto.String() {
		case "DNSCrypt":return fetchDNSCryptServerInfo(proxy, name, stamp, isNew)
		case "DoH":return fetchDoHServerInfo(proxy, name, stamp, isNew)
		case "DoT":return fetchDoTServerInfo(proxy, name, stamp, isNew)
		default:return ServerInfo{}, errors.New("unsupported protocol")
	}
}

func routes(proxy *Proxy, name string) (*[]*common.Endpoint, error) {
	routes := proxy.Routes
	var relays0 = make([]*common.Endpoint, 0)
	if routes == nil {
		return &relays0, nil
	}
	relayNames, ok := (*routes)[name]
	if !ok {
		relayNames, ok = (*routes)[common.STAR]
	}
	if !ok {
		return &relays0, nil
	}
	dlog.Infof("select relays for %s", name)
	if len(relayNames) > 0 && relayNames[0] == common.STAR {
		var relays_all = make([]*common.Endpoint, len(proxy.RegisteredRelays))
		for i, registeredServer := range proxy.RegisteredRelays {
			relayAddr, err := common.ResolveEndpoint(registeredServer.Stamp.ServerAddrStr)
			if err != nil {
				return nil, err
			}
			relays_all[i] = relayAddr
			dlog.Infof("%s=>%s",registeredServer.Name, relayAddr.String())
		}
		return &relays_all, nil
	}
	var relays = make([]*common.Endpoint, len(relayNames))
	for i, relayName := range relayNames {
		var relayCandidateStamp *stamps.ServerStamp
		if len(relayName) == 0 {
			return nil, dlog.Errorf("Route declared for [%v] but an empty relay list", name)
		} else if relayStamp, err := stamps.NewServerStampFromString(relayName); err == nil {
			relayCandidateStamp = &relayStamp
		} else if _, err := common.ResolveEndpoint(relayName); err == nil {
			relayCandidateStamp = &stamps.ServerStamp{
				ServerAddrStr: relayName,
				Proto:         stamps.StampProtoTypeDNSCryptRelay,
			}
		} else {
			for _, registeredServer := range proxy.RegisteredRelays {
				if registeredServer.Name == relayName {
					relayCandidateStamp = registeredServer.Stamp
					break
				}
			}
			for _, registeredServer := range proxy.RegisteredServers {
				if registeredServer.Name == relayName {
					relayCandidateStamp = registeredServer.Stamp
					break
				}
			}
		}
		if relayCandidateStamp == nil {
			err := dlog.Errorf("Undefined relay [%v] for server [%v]", relayName, name)
			panic(err) //os.Exit(255)
			return nil, err
		}
		if relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCrypt ||
			relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCryptRelay {
			relayAddr, err := common.ResolveEndpoint(relayCandidateStamp.ServerAddrStr)
			if err != nil {
				return nil, err
			}
			relays[i] = relayAddr
			dlog.Infof("%s=>%s",relayName, relayAddr.String())
			continue
		}
		return nil, dlog.Errorf("Invalid relay [%v] for server [%v]", relayName, name)
	}
	return &relays, nil
}

func fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp *stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.Replace(string(stamp.ServerPk), ":", "", -1))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			panic(dlog.Errorf("unsupported public key for %s key=%v", name, stamp.ServerPk))
		}
		dlog.Warnf("public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}
	relays, err := routes(proxy, name)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteAddr, err := common.ResolveEndpoint(stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	resolver := &dnscrypt.Resolver{
		Name:&name,
		Identifiers:strings.Split(stamp.ProviderName, common.Delimiter),
		PublicKey:[]uint8(stamp.ServerPk),
	}
	dailFn := func(network, address string) (net.Conn, error) {
		proxies := proxy.XTransport.Proxies
		if network == "udp" && !proxies.UDPProxies() {
			network = "tcp"
		}
		var pc net.Conn
		var err error
		if !proxies.HasValue() {
			pc, err = common.Dial(network, address, proxy.LocalInterface, proxy.Timeout, -1)
		} else {
			pc, err = proxies.GetDialContext()(nil, proxy.LocalInterface, network, address)
		}
		if err == nil {
			err = pc.SetDeadline(time.Now().Add(proxy.Timeout))
		}
		return pc, err
	}
	rtt, err := dnscrypt.RetrieveServicesInfo(false, resolver, dailFn, proxy.MainProto, remoteAddr, relays)
	if err != nil {
		return ServerInfo{}, err
	}
	certInfo := &DNSCryptInfo{Resolver:resolver}
	if epring := common.LinkEPRing(*relays...); epring != nil {
		certInfo.RelayAddr = &atomic.Value{}
		certInfo.RelayAddr.Store(epring)
	}
	certInfo.IPAddr = &atomic.Value{}
	certInfo.IPAddr.Store(common.LinkEPRing(remoteAddr))
	if certInfo.RelayAddr != nil {
		certInfo.RelayAddr.Load().(*common.EPRing).Do(
		func(v interface{}){
		dlog.Infof("relay [%s*%s]=%s", name, v.(*common.EPRing).Order(), v.(*common.EPRing).String())
		})
	}
	serverInfo := ServerInfo{
		Info:               certInfo,
		Name:               name,
		Timeout:            proxy.Timeout,
		rtt:                mm.Concurrent(mm.New(Windows)),
	}
	xrtt := int(rtt.Nanoseconds() / 1000000)
	serverInfo.rtt.Add(float64(xrtt))
	certInfo.ServerInfo = &serverInfo
	return serverInfo, nil
}

func dohTestPacket(dnssec bool) (*[]byte, uint16) {
	msg := &dns.Msg{}
	msg.SetQuestion(".", dns.TypeMX)
	id := msg.Id
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
	for i,_ := range ext.Padding {
		ext.Padding[i] = 0x00
	}
	opt.Option = append(opt.Option, ext)
	bin, _ := msg.Pack()
	return &bin, id
}

func fetchDoTServerInfo(proxy *Proxy, name string, stamp *stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	dnssec := stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0
	body, msgId := dohTestPacket(dnssec)
	var rtt time.Duration
	var serverResponse *dns.Msg
	var bin *[]byte
	var err error
	var matchCert = func(state *tls.ConnectionState) error {
		if state == nil || !state.HandshakeComplete {
			errors.New("TLS handshake failed")
		}
		dlog.Infof("[%s] TLS version: %x - cipher suite: %v", name, state.Version, state.CipherSuite)
		found := false
		var wantedHash [32]byte
		for _, cert := range state.PeerCertificates {
			l := len(cert.RawTBSCertificate)
			h := sha256.Sum256(cert.RawTBSCertificate)
			h1 := sha256.Sum256(cert.Raw)
			h2 := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

			dlog.Debugf("advertised cert: [%s] [%x] [%d]", cert.Subject, h, l)
			dlog.Debugf("Fingerprint/Pin: [%s] [%s] [%x] [%s]", cert.Subject, strings.Join(cert.DNSNames, ","), h1, base64.StdEncoding.EncodeToString(h2[:]))

			for _, hash := range stamp.Hashes {
				if len(hash) == len(wantedHash) {
					copy(wantedHash[:], hash)
					if h == wantedHash {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		if !found && len(stamp.Hashes) > 0 {
			return dlog.Errorf("Certificate hash [%x] not found for [%s]", wantedHash, name)
		}
		return nil
	}
	info := &DOTInfo{}
	const retry = 3
	for tries := retry; tries > 0; tries-- {
		now := time.Now()
		if bin, err = proxy.DoTQuery(name, nil, body, matchCert); err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				continue
			} else {
				break
			}
		}
		rtt = time.Since(now)
		msg := &dns.Msg{}
		if err = msg.Unpack(*bin); err == nil {
			serverResponse = msg
			break
		}
	}
	if err != nil {
		return ServerInfo{}, err
	}
	if common.Program_dbg_full {
		bin, err := json.Marshal(serverResponse)
		if err == nil {
			jsonStr := string(bin)
			dlog.Debug("[processed request]:" + jsonStr)
		}
	}
	if serverResponse.Id != msgId {
		errMsg := "Webserver returned an unexpected response"
		dlog.Warn(errMsg)
		return ServerInfo{}, errors.New(errMsg)
	}
	xrtt := int(rtt.Nanoseconds() / 1000000)
	if isNew {
		dlog.Noticef("[%s] OK (DoT) - rtt: %dms", name, xrtt)
	} else {
		dlog.Infof("[%s] OK (DoT) - rtt: %dms", name, xrtt)
	}
	
	serverInfo := ServerInfo{
		Info:       info,
		Name:       name,
		Timeout:    proxy.Timeout,
		rtt:        mm.Concurrent(mm.New(Windows)),
	}
	serverInfo.rtt.Add(float64(xrtt))
	info.ServerInfo = &serverInfo
	return serverInfo, nil
}

func fetchDoHServerInfo(proxy *Proxy, name string, stamp *stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	dnssec := stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0
	body, msgId := dohTestPacket(dnssec)
	//body := dohTestPacket(0xcafe) english tea??? 
	var rtt time.Duration
	var serverResponse *dns.Msg
	var bin *[]byte
	var err error
	var matchCert = func(state *tls.ConnectionState) error {
		if state == nil || !state.HandshakeComplete {
			errors.New("TLS handshake failed")
		}
		protocol := state.NegotiatedProtocol
		if len(protocol) == 0 {
			protocol = "h1"
			dlog.Warnf("[%s] does not support HTTP/2", name)
		}
		dlog.Infof("[%s] TLS version: %x - protocol: %v - cipher suite: %v", name, state.Version, protocol, state.CipherSuite)
		found := false
		var wantedHash [32]byte
		for _, cert := range state.PeerCertificates {
			l := len(cert.RawTBSCertificate)
			h := sha256.Sum256(cert.RawTBSCertificate)
			h1 := sha256.Sum256(cert.Raw)
			h2 := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			dlog.Debugf("advertised cert: [%s] [%x] [%d]", cert.Subject, h, l)
			dlog.Debugf("Fingerprint/Pin: [%s] [%s] [%x] [%s]", cert.Subject, strings.Join(cert.DNSNames, ","), h1, base64.StdEncoding.EncodeToString(h2[:]))
			for _, hash := range stamp.Hashes {
				if len(hash) == len(wantedHash) {
					copy(wantedHash[:], hash)
					if h == wantedHash {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		if !found && len(stamp.Hashes) > 0 {
			return dlog.Errorf("Certificate hash [%x] not found for [%s]", wantedHash, name)
		}
		return nil
	}
	info := &DOHInfo{
		Path:       stamp.Path,
		useGet:     false,
	}
	const retry = 3
	for tries := retry; tries > 0; tries-- {
		now := time.Now()
		if bin, err = proxy.DoHQuery(name, info, nil, body, matchCert); err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				continue
			} else {
				break
			}
		}
		rtt = time.Since(now)
		msg := &dns.Msg{}
		if err = msg.Unpack(*bin); err == nil {
			serverResponse = msg
			break
		}
	}
	if err != nil {
		return ServerInfo{}, err
	}
	if common.Program_dbg_full {
		bin, err := json.Marshal(serverResponse)
		if err == nil {
			jsonStr := string(bin)
			dlog.Debug("[processed request]:" + jsonStr)
		}
	}
	if serverResponse.Id != msgId {
		errMsg := "Webserver returned an unexpected response"
		dlog.Warn(errMsg)
		return ServerInfo{}, errors.New(errMsg)
	}
	xrtt := int(rtt.Nanoseconds() / 1000000)
	if isNew {
		dlog.Noticef("[%s] OK (DoH) - rtt: %dms", name, xrtt)
	} else {
		dlog.Infof("[%s] OK (DoH) - rtt: %dms", name, xrtt)
	}
	
	serverInfo := ServerInfo{
		Info:       info,
		Name:       name,
		Timeout:    proxy.Timeout,
		rtt:        mm.Concurrent(mm.New(Windows)),
	}
	serverInfo.rtt.Add(float64(xrtt))
	info.ServerInfo = &serverInfo
	return serverInfo, nil
}
