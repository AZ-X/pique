package main

import (
	"container/list"
	"context"
	"net"
	"net/http"
	"net/url"
)

type RealProxy struct {
	list.Element
	Value              *url.URL
	EP                 *Endpoint
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
	return np.Len() == 0
}

//first 'ProxyURI' in toml then global proxy stamps by order
func (np *NestedProxy) AddGlobalProxy(e *url.URL, ep *Endpoint) {
	var rp = &RealProxy{ Value: e, EP: ep, IsGlobal: true,}
	rp.Element.Value = rp
	np.PushFront(rp)
}

func (np *NestedProxy) AddProxy(e *url.URL, ep *Endpoint) {
	var rp = &RealProxy{ Value: e, EP: ep, IsGlobal: false,}
	rp.Element.Value = rp
	np.PushBack(rp)
}

func (np *NestedProxy) GetDialContext() ProxyDialContext {
	var pdc ProxyDialContext
	pdc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, nil
	}
	return pdc
}

func (np *NestedProxy) GetTransportProxy() (ProxyDialContext, TransportProxy) {
	var pdc ProxyDialContext
	var tp TransportProxy
	pdc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, nil
	}
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
