package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"github.com/jedisct1/dlog"
	stamps "stammel"
)

const (
	DOHMediaType                    = "application/dns-message"
	DefaultKeepAlive                = 0 * time.Second
	DefaultTimeout                  = 30 * time.Second
	DoTDefaultPort                  = 853
)

type TransportHolding struct {
	*http.Transport
	*tls.Config
	*EPRing
	Name                            *string //redundant key: name of stamp for now
	DomainName                      string
	SNIShadow                       string
	SNIBlotUp                       stamps.SNIBlotUpType
	Proxies                         *NestedProxy // individual proxies chain

}

type XTransport struct {
	transports                      map[string]*TransportHolding //key: name of stamp for now
	keepAlive                       time.Duration
	timeout                         time.Duration
	tlsDisableSessionTickets        bool
	tlsCipherSuite                  []uint16
	Proxies                         *NestedProxy
}

type HTTPSContext struct {
	context.Context
}

type TLSContext struct {
	context.Context
}


func NewXTransport() *XTransport {
	xTransport := XTransport{
		keepAlive:                	DefaultKeepAlive,
		timeout:                  	DefaultTimeout,
		tlsDisableSessionTickets: 	false,
		tlsCipherSuite:           	nil,
	}
	return &xTransport
}

func (xTransport *XTransport) closeIdleConnections() {

}


//general template for all TLS conn;
func (xTransport *XTransport) buildTransport(server RegisteredServer, _ *NestedProxy) error {
	dlog.Debugf("building transport for [%s]", server.name)
	timeout := xTransport.timeout
	stamp := server.stamp
	domain, port, err := ExtractHostAndPort(stamp.ProviderName, stamps.DefaultPort)
	if err != nil {
		return err
	}
	endpoint, err := ResolveEndpoint(stamp.ServerAddrStr)
	if err != nil {
		return err
	}
	if endpoint.Port != 0 && endpoint.Port != stamps.DefaultPort {
		port = endpoint.Port
	}
	endpoint.Port = port
	epring := LinkEPRing(endpoint)
	transport := &http.Transport{
	ForceAttemptHTTP2:      true,//formal servers (DOH, DOT, https-gits, etc.) should provide H>1.1 infrastructure with tls>1.2
	DisableKeepAlives:      xTransport.keepAlive <= 0,
	DisableCompression:     true,
	MaxIdleConns:           5,
	MaxConnsPerHost:        0,
	TLSHandshakeTimeout:    1500 * time.Millisecond,
	IdleConnTimeout:        xTransport.keepAlive,
	ResponseHeaderTimeout:  timeout,
	ExpectContinueTimeout:  timeout,
	MaxResponseHeaderBytes: 4096,
	}

	th := &TransportHolding{
		Name:       &server.name,
		DomainName: domain,
		SNIShadow:  stamp.SNIShadow,
		SNIBlotUp:  stamp.SNIBlotUp,
	}
	th.Transport = transport
	th.EPRing = epring
	transport.TLSClientConfig = th.buildTLS(xTransport)
	if err := th.buildTransport(xTransport, xTransport.Proxies); err != nil {
		return err
	}
	xTransport.transports[server.name] = th
	return nil
}

func (xTransport *XTransport) buildTLS(server RegisteredServer) error {
	dlog.Debugf("building TLS for [%s]", server.name)
	stamp := server.stamp
	domain, port, err := ExtractHostAndPort(stamp.ProviderName, DoTDefaultPort)
	if err != nil {
		return err
	}
	endpoint, err := ResolveEndpoint(stamp.ServerAddrStr)
	if err != nil {
		return err
	}
	if endpoint.Port != 0 && endpoint.Port != DoTDefaultPort {
		port = endpoint.Port
	}
	endpoint.Port = port
	epring := LinkEPRing(endpoint)
	th := &TransportHolding{
		Name:       &server.name,
		DomainName: domain,
		SNIShadow:  stamp.SNIShadow,
		SNIBlotUp:  stamp.SNIBlotUp,
	}
	th.EPRing = epring
	th.Config = th.buildTLS(xTransport)
	xTransport.transports[server.name] = th
	return nil
}

func (th *TransportHolding) buildTLS(xTransport *XTransport) (cfg *tls.Config) {
	cfg = &tls.Config{
		SessionTicketsDisabled: xTransport.tlsDisableSessionTickets,
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		DynamicRecordSizingDisabled: true,
		InsecureSkipVerify: th.SNIBlotUp != stamps.SNIBlotUpTypeDefault,
	}
	if !xTransport.tlsDisableSessionTickets {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	}
	if xTransport.tlsCipherSuite != nil {
		cfg.PreferServerCipherSuites = false
		cfg.CipherSuites = xTransport.tlsCipherSuite
	}
	cfg.ServerName = th.DomainName
	if cfg.InsecureSkipVerify {
		dlog.Debugf("SNI setup for [%s]", *th.Name)
		switch th.SNIBlotUp {
			case stamps.SNIBlotUpTypeOmit:    cfg.ServerName = ""
			case stamps.SNIBlotUpTypeIPAddr:  cfg.ServerName = th.EPRing.IP.String()
			case stamps.SNIBlotUpTypeMoniker: cfg.ServerName = th.SNIShadow
		}
		cfg.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, len(certificates))
			for i, asn1Data := range certificates {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("tls: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}
			opts := x509.VerifyOptions{
				Roots:         cfg.RootCAs,
				DNSName:       th.SNIShadow, //SNIShadow must be a known trusted alias of the host
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs {
				opts.Intermediates.AddCert(cert)
			}
			for _, cert := range certs {
				_, err := cert.Verify(opts)
				if err == nil {
					return nil
				} else {
					dlog.Debugf("[%v]", err)
				}
			}
			return errors.New("VerifyPeerCertificate failed")
		}
	}
	return cfg
}

func (th *TransportHolding) buildTransport(xTransport *XTransport, proxies *NestedProxy) error {
	transport := th.Transport
	if proxies != nil {
		dc, pf := proxies.GetTransportProxy()
		transport.Proxy = pf
		transport.DialTLSContext = dc
		return nil
	}
	alive := xTransport.keepAlive
	cfg := transport.TLSClientConfig

	getDialContext := func(t *TransportHolding, ctx context.Context, netw, addr string, isTLS bool) (net.Conn, error) {
		if strings.HasSuffix(addr, t.DomainName) {
			dlog.Criticalf("mismatch addr for TransportHolding(%s): [%s]", t.Name, addr)
			return nil, errors.New("mismatch TransportHolding")
		}
		addr = t.EPRing.String()
		t.EPRing = t.EPRing.Next()
		dialer := &net.Dialer{Timeout: 2000 * time.Millisecond, KeepAlive: alive, FallbackDelay: -1}
		if isTLS {
			return tls.DialWithDialer(dialer, netw, addr, cfg)
		} else {
			return dialer.DialContext(ctx, netw, addr)
		}
	}
	transport.DialTLSContext = func(ctx context.Context, netw, addr string) (net.Conn, error) {
		c, err := getDialContext(th, ctx, netw, addr, true)
		if err != nil {
			if neterr, ok := err.(net.Error); !ok || !neterr.Timeout() {
				dlog.Debugf("DialTLSContext encountered: [%v]", err)
			}
			return nil, err
		}
		return c, c.(*tls.Conn).Handshake()
	}
	return nil
}

// I don't foresee any benefit from dtls, so let's wait for DNS over QUIC 
func (xTransport *XTransport) FetchDoT(name string, serverProto string, ctx *TLSContext, body *[]byte, timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	th, found := xTransport.transports[name]
	if !found {
		dlog.Fatalf("name [%s] not found for transports", name)
		return nil, errors.New("name not found for transports")
	}
	return xTransport.fetchDoT(th, serverProto, ctx, body, timeout, cbs...)
}

func (xTransport *XTransport) fetchDoT(th *TransportHolding, _ string, ctx *TLSContext, msg *[]byte, timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	var err error
	var conn net.Conn
	var response []byte
	goto Go
Error:
	return nil, err
Go:
	if timeout <= 0 {
		timeout = xTransport.timeout
	}
	proxies := xTransport.Proxies.Merge(th.Proxies)
	if proxies == nil {
		dialer := &net.Dialer{Deadline: time.Now().Add(timeout), KeepAlive: xTransport.keepAlive, FallbackDelay: -1}
		if ctx == nil {
			conn, err = net.Dial("tcp", th.EPRing.String())
		} else {
			conn, err = dialer.DialContext(ctx, "tcp", th.EPRing.String())
		}
	} else {
		conn, err = xTransport.Proxies.GetDialContext()(ctx, "tcp", th.EPRing.String())
	}
	if err != nil {
		goto Error
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, th.Config)
	err = tlsConn.Handshake()
	if err != nil {
		goto Error
	}
	for _, cb := range cbs {
		switch cb := cb.(type) {
			case func(*tls.ConnectionState) error:
				cs := tlsConn.ConnectionState()
				if err = cb(&cs); err != nil {
					goto Error
				}
			default:
				dlog.Errorf("unhandled callback(T=%T) calling fetchDoT", cb)
		}
	}
	for tries := 2; tries > 0; tries-- {
		if err = WriteDP(tlsConn, *msg); err != nil {
			program_dbg_full_log("FetchDoT E01")
			continue
		}
		if response, err = ReadDP(tlsConn); err == nil {
			break
		}
		program_dbg_full_log("retry on timeout or <-EOF msg")
	}
	if err != nil {
		program_dbg_full_log("FetchDoT E02")
		goto Error
	}

	return response, nil
}


func (xTransport *XTransport) FetchHTTPS(name string, path string, method string, doh bool, ctx *HTTPSContext, body *[]byte, timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	th, found := xTransport.transports[name]
	if !found {
		dlog.Fatalf("name [%s] not found for transports", name)
		return nil, errors.New("name not found for transports")
	}
	return xTransport.fetchHTTPS(th, path, method, doh, ctx, body, timeout, cbs...)
}

func (xTransport *XTransport) fetchHTTPS(th *TransportHolding, path string, method string, doh bool, ctx *HTTPSContext, body *[]byte, timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	if timeout <= 0 {
		timeout = xTransport.timeout
	}
	client := http.Client{Transport: th.Transport, Timeout: timeout}
	// User-Agent. If set to nil or empty string, then omit it. Otherwise if not mentioned, include the default.
	header := map[string][]string{"User-Agent": {""}}
	url := &url.URL{
		Scheme: "https",
		Host:   th.DomainName,
		Path:   path,
	}
	if doh {
		header["accept"] = []string{DOHMediaType}
		if method == "POST" {
			header["content-type"] = []string{DOHMediaType}
		} else if method == "GET" {
			qs := url.Query()
			//rfc8484 single variable "dns" is defined as the content of the DNS request
			encBody := base64.RawURLEncoding.EncodeToString(*body)
			qs.Add("dns", encBody)
			url.RawQuery = qs.Encode()
		}
	}

	//rfc8484
	//The URI Template defined in this document is processed without any variables when the HTTP method is POST
	//if body != nil {
	//	h := sha512.Sum512(*body)
	//	qs := url.Query()
	//	qs.Add("body_hash", hex.EncodeToString(h[:32]))
	//	url2 := *url
	//	url2.RawQuery = qs.Encode()
	//	url = &url2
	//}

	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Close:  xTransport.keepAlive <= 0,
	}
	if ctx != nil {
		req.WithContext(ctx)
	}
	if method == "POST" && body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = ioutil.NopCloser(bytes.NewReader(*body))
	}
	resp, err := client.Do(req)
	if err == nil {
		if resp == nil {
			err = errors.New("Webserver returned an error")
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = errors.New(resp.Status)
		}
	} else {
		th.Transport.CloseIdleConnections()
	}
	if err != nil {
		dlog.Debugf("request error-[%s]", err)
		if xTransport.tlsCipherSuite != nil && strings.Contains(err.Error(), "handshake failure") {
			dlog.Error("TLS handshake failure - Try changing or deleting the tls_cipher_suite value in the configuration file")
		}
		goto Error
	}
	for _, cb := range cbs {
		switch cb := cb.(type) {
			case func(*tls.ConnectionState) error:
				if err = cb(resp.TLS); err != nil {
					goto Error
				}
			default:
				dlog.Errorf("unhandled callback(T=%T) calling fetchHTTPS", cb)
		}
	}
	var size int64
	size = MaxHTTPBodyLength
	if resp.ContentLength > 0 {
		size = Min64(resp.ContentLength, size)
	}
	bin, err := ioutil.ReadAll(io.LimitReader(resp.Body, size))
	if err != nil {
		goto Error
	}
	resp.Body.Close()
	return bin, nil
}

func (xTransport *XTransport) Get(name string, path string, ctx *HTTPSContext, timeout time.Duration) ([]byte, error) {
	return xTransport.FetchHTTPS(name, path, "GET", false, ctx, nil, timeout)
}

func (xTransport *XTransport) Post(name string, path string, ctx *HTTPSContext, body *[]byte, timeout time.Duration) ([]byte, error) {
	return xTransport.FetchHTTPS(name, path, "POST", false, ctx, body, timeout)
}

