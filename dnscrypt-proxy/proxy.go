package main

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"io"
	"time"
	"sync"
	"sync/atomic"
	
	clocksmith "github.com/jedisct1/go-clocksmith"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sync/semaphore"
)

const (
	EMPTY                       = "-"
	NonSvrName                  = EMPTY
)

type Proxy struct {
	userName                      string
	child                         bool
	proxyPublicKey                [32]byte
	proxySecretKey                [32]byte
	ephemeralKeys                 bool
	serversInfo                   ServersInfo
	timeout                       time.Duration
	certRefreshDelay              time.Duration
	certRefreshDelayAfterFailure  time.Duration
	certIgnoreTimestamp           bool
	mainProto                     string
	listenAddresses               []string
	daemonize                     bool
	registeredServers             []RegisteredServer
	registeredRelays              []RegisteredServer
	pluginBlockIPv6               bool
	pluginBlockUnqualified        bool
	pluginBlockUndelegated        bool
	cache                         bool
	cacheSize                     int
	cacheNegMinTTL                uint32
	cacheNegMaxTTL                uint32
	cacheMinTTL                   uint32
	cacheMaxTTL                   uint32
	rejectTTL                     uint32
	cloakTTL                      uint32
	queryLogFile                  string
	queryLogFormat                string
	queryLogIgnoredQtypes         []string
	nxLogFile                     string
	nxLogFormat                   string
	blockNameFile                 string
	whitelistNameFile             string
	blockNameLogFile              string
	whitelistNameLogFile          string
	blockNameFormat               string
	whitelistNameFormat           string
	blockIPFile                   string
	blockIPLogFile                string
	blockIPFormat                 string
	forwardFile                   string
	cloakFile                     string
	pluginsGlobals                PluginsGlobals
	sources                       []*Source
	clientsCount                  uint32
	maxClients                    uint32
	smaxClients                   *semaphore.Weighted
	isRefreshing                  atomic.Value
	ctx                           context.Context
	cancel                        context.CancelFunc
	wg                            sync.WaitGroup
	xTransport                    *XTransport
	logMaxSize                    int
	logMaxAge                     int
	logMaxBackups                 int
	blockedQueryResponse          string
	queryMeta                     []string
	routes                        *map[string][]string
	serversWithBrokenQueryPadding []string
	showCerts                     bool
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

func (proxy *Proxy) addDNSListener(listenAddrStr string) {
	listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenTCPAddr, err := net.ResolveTCPAddr("tcp", listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	// if 'userName' is not set, continue as before
	if len(proxy.userName) <= 0 {
		if err := proxy.udpListenerFromAddr(listenUDPAddr); err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr); err != nil {
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
	go proxy.udpListener(listenerUDP.(*net.UDPConn))

	dlog.Noticef("listening to %v [TCP]", listenAddrStr)
	go proxy.tcpListener(listenerTCP.(*net.TCPListener))
}

func (proxy *Proxy) StartProxy() {
	proxy.isRefreshing.Store(false)
	for _, listenAddrStr := range proxy.listenAddresses {
		proxy.addDNSListener(listenAddrStr)
	}
	
	// if 'userName' is set and we are the parent process drop privilege and exit
	if len(proxy.userName) > 0 && !proxy.child {
		proxy.dropPrivilege(proxy.userName, FileDescriptors)
	}
	if !proxy.ephemeralKeys {
		if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
			dlog.Fatal(err)
			os.Exit(1)
		}
		if x, err1 := curve25519.X25519(proxy.proxySecretKey[:],curve25519.Basepoint); err1 != nil {
			dlog.Fatal(err1)
			os.Exit(1)
		}else {
			copy(proxy.proxyPublicKey[:], x)
		}
	}
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(registeredServer.name, registeredServer.stamp)
	}
	liveServers, err := proxy.serversInfo.refresh(proxy)
	if liveServers > 0 {
		proxy.certIgnoreTimestamp = false
	}
	if proxy.showCerts {
		os.Exit(0)
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

func (proxy *Proxy) udpListener(clientPc *net.UDPConn) {
	defer clientPc.Close()
	for {
		buffer := make([]byte, MaxDNSPacketSize-1)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			return
		}
		packet := buffer[:length]
		go func() {
			start := time.Now()
			proxy.processIncomingQuery("udp", proxy.mainProto, packet, &clientAddr, clientPc, start)
		}()
	}
}

func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr) error {
	clientPc, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}
	dlog.Noticef("listening to %v [UDP]", listenAddr)
	go proxy.udpListener(clientPc)
	return nil
}

func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener) {
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
			packet, err := ReadPrefixed(&clientPc)
			if err != nil {
				return
			}
			clientAddr := clientPc.RemoteAddr()
			proxy.processIncomingQuery("tcp", "tcp", packet, &clientAddr, clientPc, start)
		}()
	}
}

func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr) error {
	acceptPc, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	dlog.Noticef("listening to %v [TCP]", listenAddr)
	go proxy.tcpListener(acceptPc)
	return nil
}

func (proxy *Proxy) prepareForRelay(endpoint *Endpoint, encryptedQuery *[]byte) {
	anonymizedDNSHeader := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
	relayedQuery := append(anonymizedDNSHeader, endpoint.IP.To16()...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(endpoint.Port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *encryptedQuery...)
	*encryptedQuery = relayedQuery
}

func ReadPrefixed(conn *net.Conn) ([]byte, error) {
	buf := make([]byte, 2+MaxDNSPacketSize)
	packetLength, pos := -1, 0
	for {
		readnb, err := (*conn).Read(buf[pos:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				program_dbg_full_log("ReadPrefixed EOF %d", readnb)  //0
			}
			return buf, err
		}
		pos += readnb
		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength > MaxDNSPacketSize-1 {
				return buf, errors.New("Packet too large")
			}
			if packetLength < MinDNSPacketSize {
				return buf, errors.New("Packet too short")
			}
		}
		if packetLength >= 0 && pos >= 2+packetLength {
			program_dbg_full_log("[RAW packet length]: %d", packetLength)
			return buf[2 : 2+packetLength], nil
		}
	}
}

func (proxy *Proxy) exchangeDnScRypt(serverInfo *DNSCryptInfo, packet []byte, serverProto string) ([]byte, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	sharedKey , encryptedQuery , clientNonce, err := proxy.Encrypt(serverInfo, packet, serverProto)
	if err != nil {
		program_dbg_full_log("exchangeDnScRypt E01")
		goto Error
	}
	upstreamAddr := serverInfo.IPAddr
	if serverInfo.RelayAddr != nil {
		upstreamAddr = serverInfo.RelayAddr
		serverInfo.RelayAddr = serverInfo.RelayAddr.Next()
	}
	var pc net.Conn
	proxyDialer := proxy.xTransport.proxyDialer
	if proxyDialer == nil {
		pc, err = net.Dial(serverProto, upstreamAddr.String())
	} else {
		pc, err = proxyDialer.Dial(serverProto, upstreamAddr.String())
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
		proxy.prepareForRelay(serverInfo.IPAddr.Endpoint, &encryptedQuery)
	}
	var encryptedResponse []byte
	if serverProto == "udp" {
		encryptedResponse = make([]byte, MaxDNSPacketSize)
	} else {
		encryptedQuery, err = PrefixWithSize(encryptedQuery)
		if err != nil {
			program_dbg_full_log("exchangeDnScRypt E04")
			goto Error
		}
	}
	for tries := 2; tries > 0; tries-- {
		if _, err = pc.Write(encryptedQuery); err != nil {
			program_dbg_full_log("exchangeDnScRypt E05")
			continue
		}
		if serverProto == "tcp" {
			encryptedResponse, err = ReadPrefixed(&pc)
			if err == nil {
				break
			}
		} else {
			length := 0
			length, err = pc.Read(encryptedResponse)
			if err == nil {
				encryptedResponse = encryptedResponse[:length]
				program_dbg_full_log("[RAW packet length]: %d", length)
				break
			}
		}
		program_dbg_full_log("retry on timeout or <-EOF msg")
	}
	if err != nil {
		program_dbg_full_log("exchangeDnScRypt E06")
		return nil, err
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func (proxy *Proxy) ExchangeDnScRypt(serverInfo *DNSCryptInfo, request *dns.Msg, serverProto string) (*dns.Msg, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	packet, err := request.Pack()
	if err != nil {
		goto Error
	}
	bin, err := proxy.exchangeDnScRypt(serverInfo, packet, serverProto)
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

func (proxy *Proxy) clientsCountInc() (success bool) {
	if success := proxy.smaxClients.TryAcquire(1); success {
		//DO NOT CARE
		//dlog.Debugf("clients count: %d", proxy.smaxClients.Cur())
		//dlog.Debug("clients CountInc succeeded")
		return true
	}
	return false
}

func (proxy *Proxy) clientsCountDec() {
	proxy.smaxClients.Release(1)
}

func (proxy *Proxy) processIncomingQuery(clientProto string, serverProto string, query []byte, clientAddr *net.Addr, clientPc net.Conn, start time.Time) {
	pluginsState := NewPluginsState(proxy, clientProto, clientAddr, start)
	var request *dns.Msg
	goto Go
Exit:	
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals, request)
	return	
Go:	
	var response *dns.Msg
	var err error
	var serverInfo *ServerInfo
	var isRefreshing bool
	var id uint16
	var relayIndex string
	if len(query) < MinDNSPacketSize || len(query) > MaxDNSPacketSize {
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
	if !proxy.clientsCountInc() {
		dlog.Warnf("too many outgoing dnscrypt connections (max=%d)", proxy.maxClients)
		goto SvrFault
	}
	defer proxy.clientsCountDec()
	proxy.wg.Add(1)
	defer proxy.wg.Done()
	
	serverInfo = proxy.serversInfo.getOne(request, id)
	if serverInfo == nil {
		goto SvrFault
	}
	pluginsState.serverName = &(serverInfo.Name)
	serverInfo.noticeBegin(proxy)
	switch serverInfo.Proto.String() {
		case "DoH":
			pluginsState.ApplyEDNS0PaddingQueryPlugins(request)
			info := (serverInfo.Info).(*DOHInfo)
			response, err = proxy.DoHQuery(serverInfo.Name, info, nil, request)
		case "DNSCrypt":
			info := (serverInfo.Info).(*DNSCryptInfo)
			if info.RelayAddr!= nil {
				relayIndex = "*" + info.RelayAddr.Order()
			}
			response, err = proxy.ExchangeDnScRypt(info, request, serverProto)
		default:
			dlog.Fatalf("unsupported server protocol:[%s]", serverInfo.Proto.String())
			goto SvrFault
	}

	if err != nil {
		serverInfo.noticeFailure(proxy)
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
		serverInfo.noticeSuccess(proxy)
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
	if !isRefreshing {
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
	if clientProto == "udp" {
		clientPc.(net.PacketConn).WriteTo(packet, *clientAddr)
	} else if clientProto == "tcp" {
		packet, err = PrefixWithSize(packet)
		if err != nil {
			dlog.Debugf("response has a fault of prefixing size, packet size: %d, qName: %s, sName: %s", len(packet), pluginsState.qName, pluginsState.ServerName())
		}
		if clientPc != nil {
			clientPc.Write(packet)
		}
	}
	goto Exit
}

func NewProxy() *Proxy {
	return &Proxy{
		serversInfo: NewServersInfo(),
	}
}
