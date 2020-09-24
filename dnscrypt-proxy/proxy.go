package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"io"
	"time"
	"runtime/debug"
	"sync"
	"sync/atomic"
	
	clocksmith "github.com/jedisct1/go-clocksmith"
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

//these are the fingerprint of the dnscrypt protocols, keep in mind
func AnonymizedDNSHeader() []byte {
	return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
}

func CertMagic() []byte {
	return []byte{0x44, 0x4e, 0x53, 0x43}
}

func ServerMagic() []byte {
	return []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
}

type Proxy struct {
	*ProxyStartup
	timeout                       time.Duration
	certRefreshDelay              time.Duration
	certIgnoreTimestamp           bool
	calc_hash_key                 bool
	mainProto                     string
	blockedQueryResponse          string
	cacheNegMinTTL                uint32
	cacheNegMaxTTL                uint32
	cacheMinTTL                   uint32
	cacheMaxTTL                   uint32
	cloakTTL                      uint32
	LocalInterface                *string
	routes                        *map[string][]string
	registeredRelays              []RegisteredServer
	serversInfo                   *ServersInfo
	pluginsGlobals                *PluginsGlobals
	smaxClients                   *semaphore.Weighted
	isRefreshing                  *atomic.Value
	xTransport                    *XTransport
	wg                            *sync.WaitGroup
	ctx                           context.Context
	cancel                        context.CancelFunc
}

type ProxyStartup struct {
	sources                       []*Source
	registeredServers             []RegisteredServer
	queryLogFile                  string
	queryLogFormat                string
	nxLogFile                     string
	nxLogFormat                   string
	blockNameFile                 string
	blockNameLogFile              string
	whitelistNameLogFile          string
	blockNameFormat               string
	whitelistNameFormat           string
	blockIPLogFile                string
	blockIPFormat                 string
	cloakFile                     string
	userName                      string
	queryLogIgnoredQtypes         []string
	queryMeta                     []string
	listenAddresses               []string
	cache                         bool
	child                         bool
	pluginBlockIPv6               bool
	pluginBlockUnqualified        bool
	cacheSize                     int
	logMaxSize                    int
	logMaxAge                     int
	logMaxBackups                 int
}

func program_dbg_full_log(args ...interface{}) {
	if program_dbg_full {
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

func (proxy *Proxy) addDNSListener(listenAddrStr string, idx int) {
	
	listenAddr, err := ResolveEndpoint(listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenUDPAddr := &net.UDPAddr{IP:listenAddr.IP, Port:listenAddr.Port, Zone:listenAddr.Zone,}
	listenTCPAddr := &net.TCPAddr{IP:listenAddr.IP, Port:listenAddr.Port, Zone:listenAddr.Zone,}

	// if 'userName' is not set, continue as before
	if len(proxy.userName) <= 0 {
		if err := proxy.udpListenerFromAddr(listenUDPAddr, idx); err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr, idx); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	// if 'userName' is set and we are the parent process
	if !proxy.child {
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

	// child
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
	proxy.isRefreshing = &atomic.Value{}
	proxy.isRefreshing.Store(false)
	for idx, listenAddrStr := range proxy.listenAddresses {
		proxy.addDNSListener(listenAddrStr, idx+1)
	}
	
	// if 'userName' is set and we are the parent process drop privilege and exit
	if len(proxy.userName) > 0 && !proxy.child {
		proxy.dropPrivilege(proxy.userName, FileDescriptors)
	}
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(registeredServer.name, registeredServer.stamp)
	}
	proxy.ProxyStartup = nil
	proxy.wg = &sync.WaitGroup{}
	liveServers, err := proxy.serversInfo.refresh(proxy)
	if liveServers > 0 {
		proxy.certIgnoreTimestamp = false
	}
	if liveServers > 0 {
		dlog.Noticef("dnscrypt-proxy is ready - live servers: %d", liveServers)
	} else if err != nil {
		dlog.Error(err)
		dlog.Notice("dnscrypt-proxy is waiting for at least one server to be reachable")
	}
	if len(proxy.serversInfo.registeredServers) > 0 {
		go func() {
			for {
				debug.FreeOSMemory()
				delay := proxy.certRefreshDelay
				if liveServers <= 1 && len(proxy.serversInfo.registeredServers) != liveServers {
					delay = 100 * time.Millisecond * time.Duration((len(proxy.serversInfo.registeredServers) - liveServers))
				}
				clocksmith.Sleep(delay)
				liveServers, _ = proxy.serversInfo.refresh(proxy)
				if liveServers > 0 {
					proxy.certIgnoreTimestamp = false
				}
			}
		}()
	}
}

func (proxy *Proxy) udpListener(clientPc *net.UDPConn, idx int) {
	defer clientPc.Close()
	for {
		buffer := make([]byte, MaxDNSUDPPacketSize-1)
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
			if err = clientPc.SetDeadline(time.Now().Add(proxy.timeout + 500 * time.Millisecond)); err != nil {
				return
			}
			packet, err := ReadDP(clientPc)
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

func (proxy *Proxy) prepareForRelay(endpoint *Endpoint, encryptedQuery *[]byte) {
	relayedQuery := append(AnonymizedDNSHeader(), endpoint.IP.To16()...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(endpoint.Port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *encryptedQuery...)
	*encryptedQuery = relayedQuery
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
	program_dbg_full_log("[RAW packet length]: %d", length)
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

func (proxy *Proxy) exchangeDnScRypt(serverInfo *DNSCryptInfo, packet []byte, serverProto string) ([]byte, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	proxies := proxy.xTransport.Proxies.Merge(serverInfo.Proxies)
	if serverProto == "udp" && !proxies.UDPProxies() {
		serverProto = "tcp"
	}
	sharedKey , clientNonce, encryptedQuery, err := proxy.Encrypt(serverInfo, packet, serverProto)
	if err != nil {
		program_dbg_full_log("exchangeDnScRypt E01")
		goto Error
	}
	upstreamAddr := serverInfo.IPAddr.Load().(*EPRing)
	serverInfo.IPAddr.Store(upstreamAddr.Next())
	if serverInfo.RelayAddr != nil {
		upstreamAddr = serverInfo.RelayAddr.Load().(*EPRing)
		serverInfo.RelayAddr.Store(upstreamAddr.Next())
	}
	var pc net.Conn
	if !proxies.HasValue() {
		pc, err = Dial(serverProto, upstreamAddr.String(), proxy.LocalInterface, proxy.timeout, -1)
	} else {
		pc, err = proxies.GetDialContext()(nil, serverProto, upstreamAddr.String())
	}
	if err != nil {
		program_dbg_full_log("exchangeDnScRypt E02")
		goto Error
	}
	defer pc.Close()
	if err = pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		program_dbg_full_log("exchangeDnScRypt E03")
		goto Error
	}
	if serverInfo.RelayAddr != nil {
		proxy.prepareForRelay(serverInfo.IPAddr.Load().(*EPRing).Endpoint, &encryptedQuery)
	}
	var encryptedResponse []byte
	for tries := 2; tries > 0; tries-- {
		if err = WriteDP(pc, encryptedQuery); err != nil {
			program_dbg_full_log("exchangeDnScRypt E04")
			continue
		}
		if encryptedResponse, err = ReadDP(pc); err == nil {
			break
		}
		program_dbg_full_log("retry on timeout or <-EOF msg")
	}
	if err != nil {
		program_dbg_full_log("exchangeDnScRypt E05")
		goto Error
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce, serverProto)
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
	bin, err := proxy.exchangeDnScRypt(serverInfo, packet, proxy.mainProto)
	if err != nil {
		goto Error
	}
	response := &dns.Msg{}
	if err = response.Unpack(bin); err != nil {
		goto Error
	}
	return response, nil
}

func (proxy *Proxy) doHQuery(name string, path string, useGet bool, ctx *HTTPSContext, body *[]byte, cbs ...interface{}) ([]byte, error) {
	if useGet {
		return proxy.xTransport.FetchHTTPS(name, path, "GET", true, ctx, body, proxy.timeout, cbs...)
	}
	return proxy.xTransport.FetchHTTPS(name, path, "POST", true, ctx, body, proxy.timeout, cbs...)
}

func (proxy *Proxy) DoHQuery(name string, info *DOHInfo, ctx *HTTPSContext, request *dns.Msg, cbs ...interface{}) (*dns.Msg, error) {
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

func (proxy *Proxy) DoTQuery(name string, ctx *TLSContext, request *dns.Msg, cbs ...interface{}) (*dns.Msg, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	body, err := request.Pack()
	if err != nil {
		goto Error
	}
	bin, err := proxy.xTransport.FetchDoT(name, proxy.mainProto, ctx, &body, proxy.timeout, cbs...)
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
	pluginsState := NewPluginsState(proxy, clientProto, clientAddr, start)
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
	if len(query) < MinDNSPacketSize || len(query) > MaxDNSUDPPacketSize {
		pluginsState.returnCode = PluginsStateReject
		goto Response
	}
	request, id = pluginsState.PreEvalPlugins(proxy, query, nil)
	if pluginsState.state != PluginsStateNone {
		goto Response
	}
	//current dnscrypt-proxy are not ready for parallel things, make sure of that 
	//unless large scaling repr0grammIng
	isRefreshing = proxy.isRefreshing.Load().(bool)
	if isRefreshing {
		dlog.Warn("mute dnscrypt connections while refreshing")
		goto SvrFault
	}
	if !proxy.smaxClients.TryAcquire(1) {
		dlog.Warn("too many outgoing dnscrypt connections")
		goto SvrFault
	}
	defer proxy.smaxClients.Release(1)
	proxy.wg.Add(1)
	defer proxy.wg.Done()
	
	serverInfo = proxy.serversInfo.getOne(request, id)
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
				relayIndex = "*" + info.RelayAddr.Load().(*EPRing).Order()
			}
		default:
			dlog.Fatalf("unsupported server protocol:[%s]", serverInfo.Info.Proto())
			goto SvrFault
	}
	response, err = serverInfo.Info.Query(proxy, request)
	if err != nil {
		serverInfo.rtt.Add(float64(proxy.timeout.Nanoseconds() / 1000000))
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
					response.Rcode = dns.RcodeServerFailure //prevent cache, no redirection to tcp from udp
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
	if err = WriteDP(clientPc, packet, clientAddr); err != nil {
		dlog.Debug(err)
	}
	goto Exit
}

func NewProxy() *Proxy {
	return &Proxy{
		serversInfo: NewServersInfo(),
	}
}
