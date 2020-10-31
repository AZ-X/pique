package dns

import (
	"context"
	"net"
	"os"
	"time"
	"runtime/debug"
	"sync"
	"sync/atomic"
	
	clocksmith "github.com/jedisct1/go-clocksmith"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/behaviors"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/protocols/dnscrypt"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/protocols/tls"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/services"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"golang.org/x/sync/semaphore"
)

const (
	EMPTY                       = "-"
	NonSvrName                  = EMPTY
)

var (
	FileDescriptors   = make([]*os.File, 0)
	FileDescriptorNum = 0
)


type Proxy struct {
	*ProxyStartup
	Timeout                       time.Duration
	CertRefreshDelay              time.Duration
	Calc_hash_key                 bool
	MainProto                     string
	BlockedQueryResponse          string
	CacheNegMinTTL                uint32
	CacheNegMaxTTL                uint32
	CacheMinTTL                   uint32
	CacheMaxTTL                   uint32
	CloakTTL                      uint32
	LocalInterface                *string
	Routes                        *map[string][]string
	Tags                          *map[string]map[string]interface{} //key:tag values:servers
	ListenerCfg                   *map[int]*ListenerConfiguration
	RegisteredRelays              []common.RegisteredServer
	ServersInfo                   *ServersInfo
	pluginsGlobals                *PluginsGlobals
	SmaxClients                   *semaphore.Weighted
	IsRefreshing                  *atomic.Value
	XTransport                    *tls.XTransport
	Wg                            *sync.WaitGroup
	Ctx                           context.Context
	Cancel                        context.CancelFunc
}

type ListenerConfiguration struct {
	Regex                         *services.Regexp_builder
	Groups                        *map[string]*Servers
	ServerList                    *Servers
}

type Servers struct {
	Priority                      bool
	Servers                       []*string
}

type ProxyStartup struct {
	RegisteredServers             []common.RegisteredServer
	QueryLogFile                  string
	QueryLogFormat                string
	NxLogFile                     string
	NxLogFormat                   string
	BlockNameFile                 string
	BlockNameLogFile              string
	WhitelistNameLogFile          string
	BlockNameFormat               string
	WhitelistNameFormat           string
	BlockIPLogFile                string
	BlockIPFormat                 string
	CloakFile                     string
	UserName                      string
	QueryLogIgnoredQtypes         []string
	QueryMeta                     []string
	ListenAddresses               []string
	Cache                         bool
	Child                         bool
	PluginBlockIPv6               bool
	PluginBlockUnqualified        bool
	CacheSize                     int
	LogMaxSize                    int
	LogMaxAge                     int
	LogMaxBackups                 int
}

func (proxy *Proxy) addDNSListener(listenAddrStr string, idx int) {
	
	listenAddr, err := common.ResolveEndpoint(listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenUDPAddr := &net.UDPAddr{IP:listenAddr.IP, Port:listenAddr.Port, Zone:listenAddr.Zone,}
	listenTCPAddr := &net.TCPAddr{IP:listenAddr.IP, Port:listenAddr.Port, Zone:listenAddr.Zone,}

	// if 'UserName' is not set, continue as before
	if len(proxy.UserName) <= 0 {
		if err := proxy.udpListenerFromAddr(listenUDPAddr, idx); err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr, idx); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	// if 'UserName' is set and we are the parent process
	if !proxy.Child {
		// parent
		listenerUDP, err := net.ListenUDP("udp", listenUDPAddr)
		if err != nil {
			dlog.Fatal(err)
		}
		listenerTCP, err := net.ListenTCP("tcp", listenTCPAddr)
		if err != nil {
			dlog.Fatal(err)
		}

		fdUDP, err := listenerUDP.File() // On Windows, the File method of UDPConn is not implemented.
		if err != nil {
			dlog.Fatalf("failed to switch to a different user: %v", err)
		}
		fdTCP, err := listenerTCP.File() // On Windows, the File method of TCPListener is not implemented.
		if err != nil {
			dlog.Fatalf("failed to switch to a different user: %v", err)
		}
		defer listenerUDP.Close()
		defer listenerTCP.Close()
		FileDescriptors = append(FileDescriptors, fdUDP)
		FileDescriptors = append(FileDescriptors, fdTCP)
		return
	}

	// Child
	listenerUDP, err := net.FilePacketConn(os.NewFile(uintptr(3+FileDescriptorNum), "listenerUDP"))
	if err != nil {
		dlog.Fatalf("failed to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	listenerTCP, err := net.FileListener(os.NewFile(uintptr(3+FileDescriptorNum), "listenerTCP"))
	if err != nil {
		dlog.Fatalf("failed to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	dlog.Noticef("listening to %v [UDP]", listenUDPAddr)
	go proxy.udpListener(listenerUDP.(*net.UDPConn), idx)

	dlog.Noticef("listening to %v [TCP]", listenAddrStr)
	go proxy.tcpListener(listenerTCP.(*net.TCPListener), idx)
}

func (proxy *Proxy) StartProxy() {
	proxy.IsRefreshing = &atomic.Value{}
	proxy.IsRefreshing.Store(false)
	for idx, listenAddrStr := range proxy.ListenAddresses {
		proxy.addDNSListener(listenAddrStr, idx+1)
	}
	
	// if 'UserName' is set and we are the parent process drop privilege and exit
	if len(proxy.UserName) > 0 && !proxy.Child {
		behaviors.DropPrivilege(proxy.UserName, FileDescriptors)
	}
	for _, registeredServer := range proxy.RegisteredServers {
		proxy.ServersInfo.registerServer(registeredServer.Name, registeredServer.Stamp)
	}
	proxy.ProxyStartup = nil
	proxy.Wg = &sync.WaitGroup{}
	liveServers, err := proxy.ServersInfo.refresh(proxy)
	if liveServers > 0 {
		dlog.Noticef("dnscrypt-proxy is ready - live servers: %d", liveServers)
	} else if err != nil {
		dlog.Error(err)
		dlog.Notice("dnscrypt-proxy is waiting for at least one server to be reachable")
	}
	if len(proxy.ServersInfo.RegisteredServers) > 0 {
		go func() {
			for {
				debug.FreeOSMemory()
				delay := proxy.CertRefreshDelay
				if liveServers <= 1 && len(proxy.ServersInfo.RegisteredServers) != liveServers {
					delay = 100 * time.Millisecond * time.Duration((len(proxy.ServersInfo.RegisteredServers) - liveServers))
				}
				clocksmith.Sleep(delay)
				liveServers, _ = proxy.ServersInfo.refresh(proxy)
			}
		}()
	}
}

func (proxy *Proxy) udpListener(clientPc *net.UDPConn, idx int) {
	defer clientPc.Close()
	for {
		buffer := make([]byte, common.MaxDNSUDPPacketSize-1)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			return
		}
		packet := buffer[:length]
		go func() {
			start := time.Now()
			proxy.processIncomingQuery("udp", packet, &clientAddr, clientPc, start, idx)
		}()
	}
}

func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr, idx int) error {
	clientPc, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}
	dlog.Noticef("listening to %v [UDP]", listenAddr)
	go proxy.udpListener(clientPc, idx)
	return nil
}

func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener, idx int) {
	defer acceptPc.Close()
	for {
		clientPc, err := acceptPc.Accept()
		if err != nil {
			continue
		}
		go func() {
			start := time.Now()
			defer clientPc.Close()
			if err = clientPc.SetDeadline(time.Now().Add(proxy.Timeout + 500 * time.Millisecond)); err != nil {
				return
			}
			packet, err := common.ReadDP(clientPc)
			if err != nil {
				return
			}
			clientAddr := clientPc.RemoteAddr()
			proxy.processIncomingQuery("tcp", packet, &clientAddr, clientPc, start, idx)
		}()
	}
}

func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr, idx int) error {
	acceptPc, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	dlog.Noticef("listening to %v [TCP]", listenAddr)
	go proxy.tcpListener(acceptPc, idx)
	return nil
}

func (proxy *Proxy) ExchangeDnScRypt(serverInfo *DNSCryptInfo, request *dns.Msg) (*dns.Msg, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	packet, err := request.Pack()
	if err != nil {
		goto Error
	}

	var service *dnscrypt.Service
	if len(serverInfo.V2_Services) != 0 {
		service = serverInfo.V2_Services[0].Service
	} else if len(serverInfo.V1_Services) != 0 {
		service = serverInfo.V1_Services[0].Service
	}
	upstreamAddr := serverInfo.IPAddr.Load().(*common.EPRing)
	upstream := upstreamAddr.Endpoint
	serverInfo.IPAddr.Store(upstreamAddr.Next())
	var relay *common.Endpoint
	if serverInfo.RelayAddr != nil {
		relayAddr := serverInfo.RelayAddr.Load().(*common.EPRing)
		relay = relayAddr.Endpoint
		serverInfo.RelayAddr.Store(relayAddr.Next())
	}
	dailFn := func(network, address string) (net.Conn, error) {
		proxies := proxy.XTransport.Proxies.Merge(serverInfo.Proxies)
		if network == "udp" && !proxies.UDPProxies() {
			network = "tcp"
		}
		var pc net.Conn
		var err error
		if !proxies.HasValue() {
			pc, err = common.Dial(network, address, proxy.LocalInterface, proxy.Timeout, -1)
		} else {
			pc, err = proxies.GetDialContext()(nil, network, address)
		}
		if err == nil {
			err = pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
		}
		return pc, err
	}
	bin, _, err := dnscrypt.Query(dailFn, proxy.MainProto, service, packet, upstream, relay)
	if err != nil {
		goto Error
	}
	response := &dns.Msg{}
	if err = response.Unpack(bin); err != nil {
		goto Error
	}
	return response, nil
}

func (proxy *Proxy) doHQuery(name string, path string, useGet bool, ctx *tls.HTTPSContext, body *[]byte, cbs ...interface{}) ([]byte, error) {
	if useGet {
		return proxy.XTransport.FetchHTTPS(name, path, "GET", true, ctx, body, proxy.Timeout, cbs...)
	}
	return proxy.XTransport.FetchHTTPS(name, path, "POST", true, ctx, body, proxy.Timeout, cbs...)
}

func (proxy *Proxy) DoHQuery(name string, info *DOHInfo, ctx *tls.HTTPSContext, request *dns.Msg, cbs ...interface{}) (*dns.Msg, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	body, err := request.Pack()
	if err != nil {
		goto Error
	}
	bin, err := proxy.doHQuery(name, info.Path, info.useGet, ctx, &body, cbs...)
	if err != nil {
		goto Error
	}
	response := &dns.Msg{}
	if err = response.Unpack(bin); err != nil {
		goto Error
	}
	return response, nil
}

func (proxy *Proxy) DoTQuery(name string, ctx *common.TLSContext, request *dns.Msg, cbs ...interface{}) (*dns.Msg, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	body, err := request.Pack()
	if err != nil {
		goto Error
	}
	bin, err := proxy.XTransport.FetchDoT(name, proxy.MainProto, ctx, &body, proxy.Timeout, cbs...)
	if err != nil {
		goto Error
	}
	response := &dns.Msg{}
	if err = response.Unpack(bin); err != nil {
		goto Error
	}
	return response, nil
}

func (proxy *Proxy) processIncomingQuery(clientProto string, query []byte, clientAddr *net.Addr,
 clientPc net.Conn, start time.Time, idx int) {
	pluginsState := NewPluginsState(proxy, clientProto, clientAddr, start, idx)
	var request *dns.Msg
	goto Go
Exit:
	pluginsState.ApplyLoggingPlugins(proxy.pluginsGlobals, request)
	pluginsState = nil
	return
Go:
	var response *dns.Msg
	var err error
	var serverInfo *ServerInfo
	var isRefreshing bool
	var id uint16
	var relayIndex string
	var timer time.Time
	if len(query) < common.MinDNSPacketSize || len(query) > common.MaxDNSUDPPacketSize {
		pluginsState.returnCode = PluginsStateReject
		goto Response
	}
	request, id = pluginsState.PreEvalPlugins(proxy, query, nil)
	if pluginsState.state != PluginsStateNone {
		goto Response
	}
	//current dnscrypt-proxy are not ready for parallel things, make sure of that 
	//unless large scaling repr0grammIng
	isRefreshing = proxy.IsRefreshing.Load().(bool)
	if isRefreshing {
		dlog.Warn("mute dnscrypt connections while refreshing")
		goto SvrFault
	}
	if !proxy.SmaxClients.TryAcquire(1) {
		dlog.Warn("too many outgoing dnscrypt connections")
		goto SvrFault
	}
	defer proxy.SmaxClients.Release(1)
	proxy.Wg.Add(1)
	defer proxy.Wg.Done()
	
	serverInfo = proxy.ServersInfo.getOne(pluginsState, id)
	if serverInfo == nil {
		goto SvrFault
	}
	pluginsState.serverName = &(serverInfo.Name)
	timer = time.Now()
	switch serverInfo.Info.Proto() {
		case "DoH", "DoT":
			pluginsState.ApplyEDNS0PaddingQueryPlugins(request)
		case "DNSCrypt":
			info := (serverInfo.Info).(*DNSCryptInfo)
			if info.RelayAddr!= nil {
				relayIndex = common.STAR + info.RelayAddr.Load().(*common.EPRing).Order()
			}
		default:
			dlog.Fatalf("unsupported server protocol:[%s]", serverInfo.Info.Proto())
			goto SvrFault
	}
	response, err = serverInfo.Info.Query(proxy, request)
	if err != nil {
		serverInfo.rtt.Add(float64(proxy.Timeout.Nanoseconds() / 1000000))
		if neterr, ok := err.(net.Error); ok && neterr.Timeout(){
			pluginsState.returnCode = PluginsReturnCodeServerTimeout
			dlog.Debugf("%v [%s]", err, pluginsState.ServerName())
		}else {
			pluginsState.returnCode = PluginsReturnCodeServFail
			dlog.Errorf("%v [%s]", err, pluginsState.ServerName())
		}
		if stale, ok := pluginsState.sessionData["stale"]; ok {
			dlog.Warnf("serving stale response, curErr:[%v]", err)
			response = stale.(*dns.Msg)
			pluginsState.returnCode = PluginsReturnCodePass	
			goto Response
		}
	} else {
		elapsed := time.Since(timer).Nanoseconds() / 1000000
		serverInfo.rtt.Add(float64(elapsed))
	}
	goto Response
SvrFault:
	pluginsState.returnCode = PluginsReturnCodeServFail	
Response:
	response = pluginsState.PostEvalPlugins(proxy, request, response, id)
	if response == nil {
		goto Exit
	}
	if clientProto == "udp" {
		if response.Len() > pluginsState.maxUnencryptedUDPSafePayloadSize {
			response.Truncate(pluginsState.maxUnencryptedUDPSafePayloadSize)
			if response.Truncated {
				dlog.Debugf("response has been truncated, qName: %s, sName: %s", pluginsState.qName, pluginsState.ServerName())
			}
		}
	}
	if !isRefreshing {
		answer := EMPTY
		for _, asr := range response.Answer {
			switch asr.Header().Rrtype {
			case dns.TypeA:
				answer = asr.(*dns.A).A.String()
				break
			case dns.TypeAAAA:
				answer = asr.(*dns.AAAA).AAAA.String()
				break
			}
		}
		if pluginsState.ServerName() == NonSvrName {
			question := EMPTY
			if len(response.Question) > 0 {
				question = request.Question[0].Name
			}
			dlog.Debugf("ID: %5d I: |%-15s| O: |%-15s| Code:%s", response.Id, question, answer, dns.RcodeToString[response.Rcode])
		} else {
			if answer == EMPTY {
				if response.Truncated {
					answer += " **Truncated**"
					response.Rcode = dns.RcodeServerFailure //prevent Cache, no redirection to tcp from udp
				} else {
					answer += " " + dns.RcodeToString[response.Rcode]
				}
			}
			dlog.Debugf("ID: %5d O: |%-15s| [%s]", response.Id, answer, pluginsState.ServerName() + relayIndex)
		}
	}
	packet, err := response.Pack()
	if err != nil {
		dlog.Errorf("dns packing error: %v", err)
		goto Exit
	}
	if err = common.WriteDP(clientPc, packet, clientAddr); err != nil {
		dlog.Debug(err)
	}
	goto Exit
}

func NewProxy() *Proxy {
	return &Proxy{
		ServersInfo: NewServersInfo(),
	}
}
