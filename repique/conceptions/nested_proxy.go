package conceptions

import (
	"bufio"
	"container/list"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
	
	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/protocols/socks5"
)

type realProxy struct {
	*url.URL
	*common.Endpoint
	IsGlobal           bool
}

type ProxyDialContext func(ctx context.Context, ifi *string, network, addr string) (net.Conn, error)

// socks5 and http(s) proxy chain
type NestedProxy struct {
	*list.List
}

func InitProxies() *NestedProxy {
	l := &NestedProxy{}
	l.Init()
	return l
}

func (np *NestedProxy) HasValue() bool {
	return np != nil && np.Len() == 0
}

func (np *NestedProxy) UDPProxies() bool {
	if !np.HasValue() {
		return true
	}
	for e := np.Front(); e != nil; e = e.Next() {
		rp := e.Value.(*realProxy)
		if rp.Scheme != "socks5" {
			return false
		}
	}
	return true
}

//first 'ProxyURI' in toml then global proxy stamps by order
func (np *NestedProxy) AddGlobalProxy(uri *url.URL, ep *common.Endpoint) {
	ep.Port, _ = strconv.Atoi(uri.Port())
	var rp = &realProxy{URL: uri, Endpoint: ep, IsGlobal: true,}
	np.PushFront(rp)
}

func (np *NestedProxy) AddProxy(uri *url.URL, ep *common.Endpoint) {
	ep.Port, _ = strconv.Atoi(uri.Port())
	var rp = &realProxy{URL: uri, Endpoint: ep, IsGlobal: false,}
	np.PushBack(rp)
}

func (np *NestedProxy) GetDialContext() ProxyDialContext {
	var pdc ProxyDialContext
	var err error
	pdc = func(ctx context.Context, ifi *string, network, addr string) (net.Conn, error) {
		var connTCP net.Conn
		var connUDP net.Conn
		var udp bool = network == "udp"
		if ctx == nil {
			ctx = context.Background()
		}
		if udp && !np.UDPProxies() {
			panic("unsupported network on calling NestedProxy:getDialContext")
		}
		pilotConnect := func(rp *realProxy) error {
			var ep *common.Endpoint
			if ep, err = common.ResolveEndpoint(rp.Host); err != nil {
				ep = rp.Endpoint
			}
			if ep == nil {
				 return errors.New("check code: IP of primary proxy is not granted assignments")
			}
			// A proxy should be fast; If its latency time can't be guaranteed, drop it.
			if connTCP, err = common.Dial("tcp", ep.String(), ifi, 500*time.Millisecond, -1); err != nil {
				return err
			}
			return nil
		}
		var connect func(el *list.Element, opts ...string) error
		connect = func(el *list.Element, opts ...string) error {
			var target string
			if len(opts) > 0 {
				target = opts[0]
			} else 	if ne := el.Next(); ne != nil {
				target = ne.Value.(*realProxy).Host
			} else {
				target = addr
			}
			rp := el.Value.(*realProxy)
			if el.Prev() == nil {
				if err = pilotConnect(rp); err != nil {
					return err
				}
			}
			switch rp.Scheme {
			case "socks5":
						sd := &socks5.SocksDialer{}
						if rp.User != nil {
							password, _ := rp.User.Password()
							sunp := &socks5.SocksUsernamePassword{UserName:rp.User.Username(),Password:password,}
							sd.Authenticate = sunp.Authenticate
							sd.AuthMethods = []socks5.SocksAuthMethod{socks5.SocksAuthMethodUsernamePassword}
						}
						var cmd socks5.SocksCommand
						if len(opts) == 0 && (!udp || el.Next() != nil) {
							cmd = socks5.SocksCmdConnect
						} else {
							cmd = socks5.SockscmdUDP
						}
						sd.SetCMD(cmd)
						var sa *socks5.SocksAddr
						if sa, err = sd.Connect(ctx, connTCP, network, target); err == nil {
							if cmd == socks5.SockscmdUDP {
								connUDP = socks5.NewUdpSocksConn(sa, connTCP, connUDP)
								if el.Prev() == nil {
									var realUDP net.Conn
									if realUDP, err = common.Dial("udp", sa.String(), ifi, 500*time.Millisecond, -1); err != nil {
										return err
									}
									connUDP.(*socks5.UdpSocksConn).SetRealUDP(realUDP)
									return nil
								}
								reversed := make([]*list.Element, 0)
								for e := el; e != nil; e = e.Prev() {
									reversed = append(reversed, e)
								}
								for i := len(reversed); i > 0; i-- {
									if err = connect(reversed[i]); err != nil {
										return err
									}
								}
								if err = connect(reversed[0], sa.String()); err != nil {
									return err
								}
							}
						} else {
							return err
						}
			case "https":
						cfg := &tls.Config{
							MinVersion: tls.VersionTLS12,
							CurvePreferences: []tls.CurveID{tls.X25519},
							NextProtos: []string{"h2"},
							ServerName: rp.Hostname(),
						}
						connTCP = tls.Client(connTCP, cfg)
						fallthrough
			case "http": proxyHTTP(ctx, rp.User, target, connTCP)
			}
			return nil
		}
		for e := np.Front(); e != nil; e = e.Next() {
			if err = connect(e); err != nil {
				return nil, err
			}
		}
		if udp {
			return connUDP, nil
		}
		return connTCP, nil
	}
	return pdc
}

func proxyHTTP(ctx context.Context, u *url.Userinfo, host string, conn net.Conn) error {
	hdr := make(http.Header)
	if  u != nil {
		hdr = hdr.Clone()
		username := u.Username()
		password, _ := u.Password()
		pa := "Basic " + base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		hdr.Set("Proxy-Authorization", pa)
	}
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: host},
		Host:   host,
		Header: hdr,
	}
	
	connectCtx := ctx
	if ctx.Done() == nil {
		newCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel()
		connectCtx = newCtx
	}
	
	didReadResponse := make(chan struct{})
	var (
		resp *http.Response
		err  error
	)
	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq)
	}()
	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return connectCtx.Err()
	case <-didReadResponse:
	}
	if err != nil {
		conn.Close()
		return err
	}
	if resp.StatusCode != 200 {
		err = errors.New(resp.Status)
		conn.Close()
		return err
	}
	return nil
}

//global proxy stamps and non-global individual proxy stamps binding to resolvers Ex
func (np *NestedProxy) Merge(peer *NestedProxy) *NestedProxy {
	if np == nil {
		return peer
	}
	if peer == nil {
		return np
	}

	mnp := &NestedProxy{}
	mnp.Init()
	if el := np.Front(); el != nil && el.Value.(realProxy).IsGlobal {
		mnp.PushBackList(np.List)
		mnp.PushBackList(peer.List)
	} else {
		mnp.PushBackList(peer.List)
		mnp.PushBackList(np.List)
	}
	return mnp
}
