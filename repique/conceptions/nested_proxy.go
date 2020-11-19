package conceptions

import (
	"bufio"
	"container/list"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
	
	"github.com/AZ-X/pique/repique/common"
)

type RealProxy struct {
	list.Element
	Value              *url.URL
	EP                 *common.Endpoint
	IsGlobal           bool
}

type ProxyDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
type TransportProxy func(*http.Request) (*url.URL, error)

//it could be dynamic in case of an advanced runtime
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
		rp := e.Value.(RealProxy)
		if rp.Value.Scheme != "socks5" {
			return false
		}
	}
	return true
}


//first 'ProxyURI' in toml then global proxy stamps by order
func (np *NestedProxy) AddGlobalProxy(e *url.URL, ep *common.Endpoint) {
	ep.Port, _ = strconv.Atoi(e.Port())
	var rp = &RealProxy{ Value: e, EP: ep, IsGlobal: true,}
	rp.Element.Value = rp
	np.PushFront(rp)
}

func (np *NestedProxy) AddProxy(e *url.URL, ep *common.Endpoint) {
	ep.Port, _ = strconv.Atoi(e.Port())
	var rp = &RealProxy{ Value: e, EP: ep, IsGlobal: false,}
	rp.Element.Value = rp
	np.PushBack(rp)
}

func (np *NestedProxy) GetDialContext() ProxyDialContext {
	return np.getDialContext(false)
}

var zeroDialer net.Dialer
func (np *NestedProxy) getDialContext(trans bool) ProxyDialContext {
	var pdc ProxyDialContext
	var err error
	pdc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var conn net.Conn
		if ctx == nil {
			ctx = context.TODO()
		}
		for e := np.Front(); e != nil && (!trans || e!= np.Back()); e = e.Next() {
			rp := e.Value.(RealProxy)
			uri := rp.Value
			hostname := uri.Hostname()
			isFirst := e.Prev() == nil
			var ep *common.Endpoint
			if ep, err = common.ResolveEndpoint(hostname); err != nil {
				ep = rp.EP
			}
			if isFirst && ep == nil {
				 err = errors.New("check code: IP of primary proxy is not granted assignments")
				return nil, err
			}
			if isFirst {
				if conn, err = zeroDialer.DialContext(ctx, network, addr); err != nil {
					return nil, err
				}
			}
			cm := uri.Scheme
			switch cm {
			case "socks5":
			case "http", "https":proxyHTTP(ctx, uri.User, "", conn)
			
			}
		}
		return nil, nil
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



func (np *NestedProxy) GetTransportProxy() (ProxyDialContext, TransportProxy) {
	var pdc ProxyDialContext
	var tp TransportProxy
	pdc = np.getDialContext(true)
	tp = func(*http.Request) (*url.URL, error) {
		return nil, nil
	}
	return pdc, tp
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
	if el := np.Front(); el != nil && el.Value.(RealProxy).IsGlobal {
		mnp.PushBackList(np.List)
		mnp.PushBackList(peer.List)
	} else {
		mnp.PushBackList(peer.List)
		mnp.PushBackList(np.List)
	}
	return mnp
}
