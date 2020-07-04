package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"context"
	"time"
	
	"github.com/VividCortex/ewma"
	"github.com/jedisct1/dlog"
	stamps "stammel"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

const (
	RTTEwmaDecay = 10.0
)

type RegisteredServer struct {
	name        string
	stamp       *stamps.ServerStamp
	description string
}

type ServerBugs struct {
	incorrectPadding bool
}

type ServerInfo struct {
	Proto              stamps.StampProtoType
	MagicQuery         [8]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction CryptoConstruction
	Name               string
	Timeout            time.Duration
	Path           	   string
	IPAddr             *EPRing
	RelayAddr          *EPRing
	knownBugs          ServerBugs
	lastActionTS       time.Time
	rtt                ewma.MovingAverage
	initialRtt         int
	useGet             bool
}

type LBStrategy int

const (
	LBStrategyNone = LBStrategy(iota)
	LBStrategyP2
	LBStrategyPH
	LBStrategyFirst
	LBStrategyRandom
)

const DefaultLBStrategy = LBStrategyP2

type ServersInfo struct {
	sync.Mutex
	inner             []*ServerInfo
	registeredServers []RegisteredServer
	lbStrategy        LBStrategy
	lbEstimator       bool
}

func NewServersInfo() ServersInfo {
	return ServersInfo{lbStrategy: DefaultLBStrategy, lbEstimator: true, registeredServers: make([]RegisteredServer, 0)}
}

func (serversInfo *ServersInfo) registerServer(name string, stamp *stamps.ServerStamp) {
	newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
	for i, oldRegisteredServer := range serversInfo.registeredServers {
		if oldRegisteredServer.name == name {
			serversInfo.registeredServers[i] = newRegisteredServer
			return
		}
	}
	serversInfo.registeredServers = append(serversInfo.registeredServers, newRegisteredServer)
}

func (serversInfo *ServersInfo) refreshServer(proxy *Proxy, name string, stamp *stamps.ServerStamp) error {
	isNew := true
	for _, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			isNew = false
			break
		}
	}
	if !isNew {
		return nil
	}
	newServer, err := fetchServerInfo(proxy, name, stamp, isNew)
	if err != nil {
		dlog.Debug(err)
		return err
	}
	if name != newServer.Name {
		dlog.Fatalf("[%s] != [%s]", name, newServer.Name)
	}
	newServer.rtt = ewma.NewMovingAverage(RTTEwmaDecay)
	newServer.rtt.Set(float64(newServer.initialRtt))
	isNew = true
	for i, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			serversInfo.inner[i] = &newServer
			isNew = false
			break
		}
	}
	if isNew {
		serversInfo.inner = append(serversInfo.inner, &newServer)
		//serversInfo.registeredServers = append(serversInfo.registeredServers, RegisteredServer{name: name, stamp: stamp})
	}
	return nil
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) (int, error) {
	proxy.isRefreshing.Store(true)
	defer proxy.isRefreshing.Store(false)
	proxy.cancel()
	proxy.ctx, proxy.cancel = context.WithCancel(context.Background())
	proxy.wg.Wait()
	dlog.Notice("refreshing certificates")
	registeredServers := serversInfo.registeredServers
	liveServers := 0
	var err error
	for _, registeredServer := range registeredServers {
		if err = serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err == nil {
			liveServers++
		} 
	}
	sort.SliceStable(serversInfo.inner, func(i, j int) bool {
		return serversInfo.inner[i].initialRtt < serversInfo.inner[j].initialRtt
	})
	if(liveServers > 0) {
		inner := serversInfo.inner
		innerLen := len(inner)
		if innerLen > 1 {
			dlog.Notice("sorted latencies:")
			for i := 0; i < innerLen; i++ {
				dlog.Noticef("- %5dms %s", inner[i].initialRtt, inner[i].Name)
			}
		}
		if innerLen > 0 {
			dlog.Noticef("serve with the lowest initial latency: %s (rtt: %dms)", inner[0].Name, inner[0].initialRtt)
		}
	}
	return liveServers, err
}

func (serversInfo *ServersInfo) estimatorUpdate() {
	serversInfo.Lock()
	defer serversInfo.Unlock()
	candidate := rand.Intn(len(serversInfo.inner))
	if candidate == 0 {
		return
	}
	candidateRtt, currentBestRtt := serversInfo.inner[candidate].rtt.Value(), serversInfo.inner[0].rtt.Value()
	if currentBestRtt < 0 {
		currentBestRtt = candidateRtt
		serversInfo.inner[0].rtt.Set(currentBestRtt)
	}
	partialSort := false
	if candidateRtt < currentBestRtt {
		serversInfo.inner[candidate], serversInfo.inner[0] = serversInfo.inner[0], serversInfo.inner[candidate]
		partialSort = true
		dlog.Debugf("preferred candidate: %v (rtt: %d vs previous: %d)", serversInfo.inner[0].Name, int(candidateRtt), int(currentBestRtt))
	} else if candidateRtt > 0 && candidateRtt >= currentBestRtt*4.0 {
		if time.Since(serversInfo.inner[candidate].lastActionTS) > time.Duration(1*time.Minute) {
			serversInfo.inner[candidate].rtt.Add(MinF(MaxF(candidateRtt/2.0, currentBestRtt*2.0), candidateRtt))
			dlog.Debugf("candidate [%s], lowering its RTT from %d to %d (best: %d)", serversInfo.inner[candidate].Name, int(candidateRtt), int(serversInfo.inner[candidate].rtt.Value()), int(currentBestRtt))
			partialSort = true
		}
	}
	if partialSort {
		serversCount := len(serversInfo.inner)
		for i := 1; i < serversCount; i++ {
			if serversInfo.inner[i-1].rtt.Value() > serversInfo.inner[i].rtt.Value() {
				serversInfo.inner[i-1], serversInfo.inner[i] = serversInfo.inner[i], serversInfo.inner[i-1]
			}
		}
	}
}

func (serversInfo *ServersInfo) getOne(request *dns.Msg, id uint16) *ServerInfo {
	serversCount := len(serversInfo.inner)
	if serversCount <= 0 {
		return nil
	}
	if serversInfo.lbEstimator {
		serversInfo.estimatorUpdate()
	}
	var candidate int
	switch serversInfo.lbStrategy {
	case LBStrategyFirst:
		candidate = 0
	case LBStrategyPH:
		candidate = rand.Intn(Max(Min(serversCount, 2), serversCount/2))
	case LBStrategyRandom:
		candidate = rand.Intn(serversCount)
	default:
		candidate = rand.Intn(Min(serversCount, 2))
	}
	serverInfo := serversInfo.inner[candidate]
	if request == nil || len(request.Question) < 1 {
		dlog.Debugf("[%s](%dms)", (*serverInfo).Name, int((*serverInfo).rtt.Value()))
	} else {
		dlog.Debugf("ID: %5d I: |%-25s| [%s] %dms", id, request.Question[0].Name, (*serverInfo).Name, int((*serverInfo).rtt.Value()))
	}
	return serverInfo
}

func fetchServerInfo(proxy *Proxy, name string, stamp *stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	switch stamp.Proto.String() {
		case "DNSCrypt":return fetchDNSCryptServerInfo(proxy, name, stamp, isNew)
		case "DoH":return fetchDoHServerInfo(proxy, name, stamp, isNew)
		default:return ServerInfo{}, errors.New("unsupported protocol")
			
	}
}

func routes(proxy *Proxy, name string) ([]*Endpoint, error) {
	routes := proxy.routes
	var relays0 = make([]*Endpoint, 0)
	if routes == nil {
		return relays0, nil
	}
	relayNames, ok := (*routes)[name]
	if !ok {
		relayNames, ok = (*routes)["*"]
	}
	if !ok {
		return relays0, nil
	}
	dlog.Infof("select relays for %s", name)
	if len(relayNames) > 0 && relayNames[0] == "*" {
		var relays_all = make([]*Endpoint, len(proxy.registeredRelays))
		for i, registeredServer := range proxy.registeredRelays {
			relayAddr, err := ResolveEndpoint(registeredServer.stamp.ServerAddrStr)
			if err != nil {
				return nil, err
			}
			relays_all[i] = relayAddr
			dlog.Infof("%s=>%s",registeredServer.name, relayAddr.String())
		}
		return relays_all, nil
	}
	var relays = make([]*Endpoint, len(relayNames))
	for i, relayName := range relayNames {
		var relayCandidateStamp *stamps.ServerStamp
		if len(relayName) == 0 {
			return nil, fmt.Errorf("Route declared for [%v] but an empty relay list", name)
		} else if relayStamp, err := stamps.NewServerStampFromString(relayName); err == nil {
			relayCandidateStamp = &relayStamp
		} else if _, err := net.ResolveUDPAddr("udp", relayName); err == nil {
			relayCandidateStamp = &stamps.ServerStamp{
				ServerAddrStr: relayName,
				Proto:         stamps.StampProtoTypeDNSCryptRelay,
			}
		} else {
			for _, registeredServer := range proxy.registeredRelays {
				if registeredServer.name == relayName {
					relayCandidateStamp = registeredServer.stamp
					break
				}
			}
			for _, registeredServer := range proxy.registeredServers {
				if registeredServer.name == relayName {
					relayCandidateStamp = registeredServer.stamp
					break
				}
			}
		}
		if relayCandidateStamp == nil {
			err := fmt.Errorf("Undefined relay [%v] for server [%v]", relayName, name)
			dlog.Fatal(err) //os.Exit(255)
			return nil, err
		}
		if relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCrypt ||
			relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCryptRelay {
			relayAddr, err := ResolveEndpoint(relayCandidateStamp.ServerAddrStr)
			if err != nil {
				return nil, err
			}
			relays[i] = relayAddr
			dlog.Infof("%s=>%s",relayName, relayAddr.String())
			continue
		}
		return nil, fmt.Errorf("Invalid relay [%v] for server [%v]", relayName, name)
	}
	return relays, nil

}

func fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp *stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.Replace(string(stamp.ServerPk), ":", "", -1))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			dlog.Fatalf("unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		dlog.Warnf("public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}
	knownBugs := ServerBugs{}
	for _, buggyServerName := range proxy.serversWithBrokenQueryPadding {
		if buggyServerName == name {
			knownBugs.incorrectPadding = true
			dlog.Infof("known bug in [%v]: padded queries are not correctly parsed", name)
			break
		}
	}
	relays, err := routes(proxy, name)
	if knownBugs.incorrectPadding && relays != nil {
		relays = nil
		dlog.Warnf("[%v] is incompatible with anonymization", name)
	}
	if err != nil {
		return ServerInfo{}, err
	}
	working_relays, certInfo, rtt, err := FetchCurrentDNSCryptCert(proxy, &name, proxy.mainProto, []uint8(stamp.ServerPk), stamp.ServerAddrStr, stamp.ProviderName, isNew, relays)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteAddr, err := ResolveEndpoint(stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	relaysEP := LinkEPRing(working_relays...)
	relaysEP.Do(func(v interface{}){dlog.Infof("relay [%s*%s]=%s",name, v.(*EPRing).Order(), v.(*EPRing).String())})
	
	return ServerInfo{
		Proto:              stamps.StampProtoTypeDNSCrypt,
		MagicQuery:         certInfo.MagicQuery,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		Name:               name,
		Timeout:            proxy.timeout,
		IPAddr:            	LinkEPRing(remoteAddr),
		RelayAddr:       	LinkEPRing(working_relays...),
		initialRtt:         rtt,
		knownBugs:          knownBugs,
	}, nil
}

func dohTestPacket(dnssec bool) (*dns.Msg, uint16) {
	msg := &dns.Msg{}
	msg.SetQuestion(".", dns.TypeMX)
	id := msg.Id
	msg.SetEdns0(uint16(MaxDNSPacketSize), dnssec)
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
		ext.Padding[i] = 0xff
	}
	opt.Option = append(opt.Option, ext)
	return msg, id
}

func fetchDoHServerInfo(proxy *Proxy, name string, stamp *stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	dnssec := stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0
	body, msgId := dohTestPacket(dnssec)
	//body := dohTestPacket(0xcafe) english tea??? 
	useGet := false
	var rtt time.Duration
	var serverResponse *dns.Msg
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
		showCerts := proxy.showCerts
		found := false
		var wantedHash [32]byte
		for _, cert := range state.PeerCertificates {
			l := len(cert.RawTBSCertificate)
			h := sha256.Sum256(cert.RawTBSCertificate)

			if showCerts {
				dlog.Noticef("advertised cert: [%s] [%x] [%i]", cert.Subject, h,l)
			} else {
				dlog.Debugf("advertised cert: [%s] [%x]", cert.Subject, h)
			}
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
			return fmt.Errorf("Certificate hash [%x] not found for [%s]", wantedHash, name)
		}
		return nil
	}
	
	retry := 3
Retry:
	
	for tries := retry; tries > 0; tries-- {
		now := time.Now()
		if serverResponse, err = proxy.DoHQuery(name, stamp.Path, useGet, nil, body, matchCert); err != nil {
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			continue
		}
		}
		rtt = time.Since(now)
		break
	}
	if !useGet && err != nil {
	if neterr, ok := err.(net.Error); !ok || !neterr.Timeout() {
	if !strings.Contains(err.Error(), "tls: use of closed connection") && !strings.Contains(err.Error(), "tls: protocol is shutdown") {
		useGet = true
		dlog.Debugf("server [%s] doesn't appear to support POST; falling back to GET requests", name)
		goto Retry
	}
	}
	}
	if err != nil {
		return ServerInfo{}, err
	}
	if program_dbg_full {
		bin, err := json.Marshal(serverResponse)
		if err == nil {
			jsonStr := string(bin)
			dlog.Debug("[processed request]:" + jsonStr)
		}
	}
	respBody, _ := serverResponse.Pack()
	var rmsgId uint16
	revData := respBody[0:2];
	revData[0], revData[1] = revData[1], revData[0] 
	buf := bytes.NewReader(revData)
	err = binary.Read(buf, binary.LittleEndian, &rmsgId)
	if err != nil || len(respBody) < MinDNSPacketSize || len(respBody) > MaxDNSPacketSize ||
		msgId != rmsgId || respBody[4] != 0x00 || respBody[5] != 0x01 {
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
	return ServerInfo{
		Proto:      stamps.StampProtoTypeDoH,
		Name:       name,
		Timeout:    proxy.timeout,
		Path:		stamp.Path,
		initialRtt: xrtt,
		useGet:     useGet,
	}, nil
}

func (serverInfo *ServerInfo) noticeFailure(proxy *Proxy) {
	proxy.serversInfo.Lock()
	defer proxy.serversInfo.Unlock()
	serverInfo.rtt.Add(float64(proxy.timeout.Nanoseconds() / 1000000))
}

func (serverInfo *ServerInfo) noticeBegin(proxy *Proxy) {
	proxy.serversInfo.Lock()
	defer proxy.serversInfo.Unlock()
	serverInfo.lastActionTS = time.Now()
	
}

func (serverInfo *ServerInfo) noticeSuccess(proxy *Proxy) {
	proxy.serversInfo.Lock()
	defer proxy.serversInfo.Unlock()
	now := time.Now()
	elapsed := now.Sub(serverInfo.lastActionTS)
	elapsedMs := elapsed.Nanoseconds() / 1000000
	if elapsedMs > 0 && elapsed < proxy.timeout {
		serverInfo.rtt.Add(float64(elapsedMs))
	}
}
