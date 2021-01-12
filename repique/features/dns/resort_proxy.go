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
	"github.com/AZ-X/pique/repique/behaviors"
	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/features/dns/channels"
	"github.com/AZ-X/pique/repique/protocols/dnscrypt"
	"github.com/AZ-X/pique/repique/protocols/tls"
	"github.com/AZ-X/pique/repique/services"

	"github.com/jedisct1/dlog"
	"golang.org/x/sync/semaphore"
)

var (
	FileDescriptors   = make([]*os.File, 0)
	FileDescriptorNum = 0
)


type Proxy struct {
	*ProxyStartup
	*channels.ChannelMgr
	Timeout                       time.Duration
	CertRefreshDelay              time.Duration
	MainProto                     string
	LocalInterface                *string
	Routes                        *map[string][]string
	Tags                          *map[string]map[string]interface{} //key:tag values:servers
	ListenerCfg                   *map[int]*ListenerConfiguration
	RegisteredRelays              []common.RegisteredServer
	ServersInfo                   *ServersInfo
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
	UserName                      string
	ListenAddresses               []string
	Child                         bool
}

func (proxy *Proxy) addDNSListener(listenAddrStr string, idx int) {
	
	listenAddr, err := common.ResolveEndpoint(listenAddrStr)
	if err != nil {
		panic(err)
	}
	listenUDPAddr := &net.UDPAddr{IP:listenAddr.IP, Port:listenAddr.Port, Zone:listenAddr.Zone,}
	listenTCPAddr := &net.TCPAddr{IP:listenAddr.IP, Port:listenAddr.Port, Zone:listenAddr.Zone,}

	// if 'UserName' is not set, continue as before
	if len(proxy.UserName) <= 0 {
		if err := proxy.udpListenerFromAddr(listenUDPAddr, idx); err != nil {
			panic(err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr, idx); err != nil {
			panic(err)
		}
		return
	}

	// if 'UserName' is set and we are the parent process
	if !proxy.Child {
		// parent
		listenerUDP, err := net.ListenUDP("udp", listenUDPAddr)
		if err != nil {
			panic(err)
		}
		listenerTCP, err := net.ListenTCP("tcp", listenTCPAddr)
		if err != nil {
			panic(err)
		}

		fdUDP, err := listenerUDP.File() // On Windows, the File method of UDPConn is not implemented.
		if err != nil {
			panic(dlog.Errorf("failed to switch to a different user: [%v]", err))
		}
		fdTCP, err := listenerTCP.File() // On Windows, the File method of TCPListener is not implemented.
		if err != nil {
			panic(dlog.Errorf("failed to switch to a different user: [%v]", err))
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
		panic(dlog.Errorf("failed to switch to a different user: [%v]", err))
	}
	FileDescriptorNum++

	listenerTCP, err := net.FileListener(os.NewFile(uintptr(3+FileDescriptorNum), "listenerTCP"))
	if err != nil {
		panic(dlog.Errorf("failed to switch to a different user: [%v]", err))
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
	if len(proxy.UserName) == 0 || proxy.Child {
		proxy.Wg = &sync.WaitGroup{}
		shares := make([]int, len(proxy.ListenAddresses))
		for idx, _ := range proxy.ListenAddresses {
			shares[idx] = idx+1
		}
		proxy.Registers(shares, &stub{handler: func(s *channels.Session) error {
			goto Go
		IntFault:
			return channels.Error_Stub_Internal
		SvrFault:
			return channels.Error_Stub_SvrFault
		Timeout:
			return channels.Error_Stub_Timeout
		Go:
			if proxy.IsRefreshing.Load().(bool) {
				dlog.Warn("mute remote resolvers while refreshing")
				goto IntFault
			}
			if !proxy.SmaxClients.TryAcquire(1) {
				dlog.Warn("too many remote resolving")
				goto IntFault
			}
			defer proxy.SmaxClients.Release(1)
			proxy.Wg.Add(1)
			defer proxy.Wg.Done()
			serverInfo := proxy.ServersInfo.getOne(s)
			if serverInfo == nil {
				goto IntFault
			}
			s.ServerName = &serverInfo.Name
			timer := time.Now()
			switch serverInfo.Info.Proto() {
				case "DoH", "DoT":
				case "DNSCrypt":
					info := (serverInfo.Info).(*DNSCryptInfo)
					if info.RelayAddr!= nil {
						name := common.STAR + info.RelayAddr.Load().(*common.EPRing).Order()
						s.ExtraServerName = &name
					}
				default:
					panic("unsupported server protocol:[%s]" + serverInfo.Info.Proto())
			}
			var err error
			s.RawIn, err = serverInfo.Info.Query(proxy, s.RawOut)
			if err != nil {
				serverInfo.rtt.Add(float64(proxy.Timeout.Nanoseconds() / 1000000))
				if neterr, ok := err.(net.Error); ok && neterr.Timeout(){
					dlog.Debugf("%v [%s]", err, *s.ServerName)
					goto Timeout
				}
				dlog.Errorf("%v [%s]", err, *s.ServerName)
				goto SvrFault
			}
			elapsed := time.Since(timer).Nanoseconds() / 1000000
			serverInfo.rtt.Add(float64(elapsed))
			return nil
		}})
	}

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
	liveServers, err := proxy.ServersInfo.refresh(proxy)
	if liveServers > 0 {
		dlog.Noticef("repique is ready - live servers: %d", liveServers)
	} else if err != nil {
		dlog.Error(err)
		dlog.Notice("repique is waiting for at least one server to be reachable")
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
			proxy.processIncomingQuery("udp", packet, &clientAddr, clientPc, idx)
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
			defer clientPc.Close()
			if err = clientPc.SetDeadline(time.Now().Add(proxy.Timeout + 500 * time.Millisecond)); err != nil {
				return
			}
			packet, err := common.ReadDP(clientPc)
			if err != nil {
				return
			}
			clientAddr := clientPc.RemoteAddr()
			proxy.processIncomingQuery("tcp", packet, &clientAddr, clientPc, idx)
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

func (proxy *Proxy) ExchangeDnScRypt(serverInfo *DNSCryptInfo, request *[]byte) (*[]byte, error) {
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
			pc, err = proxies.GetDialContext()(nil, proxy.LocalInterface, network, address)
		}
		if err == nil {
			err = pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
		}
		return pc, err
	}
	bin, _, err := dnscrypt.Query(dailFn, proxy.MainProto, service, *request, upstream, relay)
	return &bin, err
}

func (proxy *Proxy) doHQuery(name string, path string, useGet bool, ctx *tls.HTTPSContext, body *[]byte, cbs ...interface{}) ([]byte, error) {
	if useGet {
		return proxy.XTransport.FetchHTTPS(name, path, "GET", true, ctx, body, proxy.Timeout, cbs...)
	}
	return proxy.XTransport.FetchHTTPS(name, path, "POST", true, ctx, body, proxy.Timeout, cbs...)
}

func (proxy *Proxy) DoHQuery(name string, info *DOHInfo, ctx *tls.HTTPSContext, request *[]byte, cbs ...interface{}) (*[]byte, error) {
	bin, err := proxy.doHQuery(name, info.Path, info.useGet, ctx, request, cbs...)
	return &bin, err
}

func (proxy *Proxy) DoTQuery(name string, ctx *common.TLSContext, request *[]byte, cbs ...interface{}) (*[]byte, error) {
	bin, err := proxy.XTransport.FetchDoT(name, proxy.MainProto, ctx, request, proxy.Timeout, cbs...)
	return &bin, err
}


type stub struct {
	handler func(*channels.Session) error
}

func (s *stub) Name() string {
	return channels.Channel_Stub
}

func (_ *stub) Init(cfg *channels.Config, f channels.FChannelByName) {
}

func (_s *stub) Handle(s *channels.Session) channels.Channel {
	if err := _s.handler(s); err == nil {
		s.LastState = channels.R_OK
	} else {
		s.LastError = err
		if s.Response != nil {
			s.LastState = channels.RCP_NOK
		} else {
			s.LastState = channels.R_NOK
		}
	}
	s.State |= s.LastState
	return nil
}

// how different
var svrName = channels.NonSvrName
func (proxy *Proxy) processIncomingQuery(clientProto string, query []byte, clientAddr *net.Addr, clientPc net.Conn, idx int) {
	session := &channels.Session{RawIn:&query, Listener:idx, ServerName:&svrName, IsUDPClient:clientProto == "udp"}
	proxy.Handle(session)
	if err := common.WriteDP(clientPc, *session.RawOut, clientAddr); err != nil {
		dlog.Debug(err)
	}
	session = nil
}

func NewProxy() *Proxy {
	return &Proxy{
		ServersInfo: NewServersInfo(),
	}
}
