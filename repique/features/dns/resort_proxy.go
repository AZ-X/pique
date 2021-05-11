package dns

import (
	"net"
	"os"
	"time"

	"github.com/AZ-X/pique/repique/behaviors"
	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/features/dns/channels"
	"github.com/AZ-X/pique/repique/features/dns/nodes"

	"github.com/jedisct1/dlog"
)

var (
	FileDescriptors   = make([]*os.File, 0)
	FileDescriptorNum = 0
)

type Proxy struct {
	*ProxyStartup
	*channels.ChannelMgr
	*nodes.NodesMgr
}

type ProxyStartup struct {
	UserName                      string
	ListenAddresses               []string
	Timeout                       time.Duration
	Child                         bool
}

func (proxy *Proxy) addDNSListener(listenAddrStr string, idx uint8) {
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
	timeout := proxy.Timeout
	go proxy.tcpListener(listenerTCP.(*net.TCPListener), idx, timeout)
}


func (proxy *Proxy) StartProxy() {
	if len(proxy.UserName) == 0 || proxy.Child {
		l := len(proxy.ListenAddresses)
		if proxy.Cfgs[0] != nil { //sp channels
			l++
			proxy.SPNoIPv6 = proxy.Cfgs[0].BlockIPv6
		}
		shares := make([]int, l)
		for i,j := l-1,len(proxy.ListenAddresses); i >= 0; i-- {
			shares[i] = j
			j--
		}
		proxy.Registers(shares, &stub{handler: func(s *channels.Session) error {
			return proxy.Query(s) //real proxy
		}})
		proxy.SP = proxy.Handle
		proxy.Ready <- nil
	}

	for idx, listenAddrStr := range proxy.ListenAddresses {
		proxy.addDNSListener(listenAddrStr, uint8(idx+1))
	}
	// if 'UserName' is set and we are the parent process drop privilege and exit
	if len(proxy.UserName) > 0 && !proxy.Child {
		behaviors.DropPrivilege(proxy.UserName, FileDescriptors)
	}
	proxy.ProxyStartup = nil
}

func (proxy *Proxy) udpListener(clientPc *net.UDPConn, idx uint8) {
	defer clientPc.Close()
	for {
		buffer := make([]byte, common.MaxDNSUDPPacketSize-1)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			return
		}
		packet := buffer[:length]
		go func() {
			proxy.processIncomingQuery(true, packet, &clientAddr, clientPc, idx)
		}()
	}
}

func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr, idx uint8) error {
	clientPc, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}
	dlog.Noticef("listening to %v [UDP]", listenAddr)
	go proxy.udpListener(clientPc, idx)
	return nil
}

func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener, idx uint8, timeout time.Duration) {
	defer acceptPc.Close()
	for {
		clientPc, err := acceptPc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer clientPc.Close()
			if err = clientPc.SetDeadline(time.Now().Add(timeout + 500 * time.Millisecond)); err != nil {
				return
			}
			packet, err := common.ReadDP(clientPc)
			if err != nil {
				return
			}
			clientAddr := clientPc.RemoteAddr()
			proxy.processIncomingQuery(false, packet, &clientAddr, clientPc, idx)
		}()
	}
}

func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr, idx uint8) error {
	acceptPc, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	dlog.Noticef("listening to %v [TCP]", listenAddr)
	timeout := proxy.Timeout
	go proxy.tcpListener(acceptPc, idx, timeout)
	return nil
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
func (proxy *Proxy) processIncomingQuery(udp bool, query []byte, clientAddr *net.Addr, clientPc net.Conn, idx uint8) {
	session := &channels.Session{RawIn:&query, Listener:idx, ServerName:&svrName, IsUDPClient:udp}
	proxy.Handle(session)
	if err := common.WriteDP(clientPc, *session.RawOut, clientAddr); err != nil {
		dlog.Debug(err)
	}
	session = nil
}
