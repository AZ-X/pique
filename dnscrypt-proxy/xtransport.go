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
	"sync/atomic"
	"time"
	_ "unsafe"

	"github.com/jedisct1/dlog"
	stamps "stammel"
)

const (
	DOHMediaType                 = "application/dns-message"
	DefaultKeepAlive             = 0 * time.Second
	DefaultTimeout               = 30 * time.Second
	DoTDefaultPort               = 853
	TLS_AES_128_GCM_SHA256       = 0x1301 // 16bit key
	TLS_AES_256_GCM_SHA384       = 0x1302 // 1st not pq ready
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303 // 2nd not pq ready
)

var (
//go:linkname varDefaultCipherSuitesTLS13 crypto/tls.varDefaultCipherSuitesTLS13
varDefaultCipherSuitesTLS13 []uint16
)

//go:linkname defaultCipherSuitesTLS13 crypto/tls.defaultCipherSuitesTLS13
func defaultCipherSuitesTLS13() []uint16

//to reduce memory payload, shift http's Transport and ensure single instance of it
//now give up calling CloseIdleConnections method which has side effect on burst connections with different cm
//since we use custom dial on Transport with variant of tls config, have to cover all the proxies usage
type TransportHolding struct {
	*tls.Config
	IPs                             *atomic.Value //*EPRing
	Name                            *string //redundant key: name of stamp for now
	DomainName                      string
	SNIShadow                       string
	SNIBlotUp                       stamps.SNIBlotUpType
	Context                         *HTTPSContext
	Proxies                         *NestedProxy // individual proxies chain
}

//upon TLS
type XTransport struct {
	*http.Transport
	transports                      map[string]*TransportHolding //key: name of stamp for now
	keepAlive                       time.Duration
	timeout                         time.Duration
	tlsDisableSessionTickets        bool
	Proxies                         *NestedProxy
	LocalInterface                  *string
}

//name, conn, err
type TLSContextDial func(ctx context.Context, network, addr string) (*string, net.Conn, error)

//soul of HTTPS
type HTTPSContext struct {
	context.Context
	TLSContextDial
}

func (c *HTTPSContext) Value(key interface{}) interface{} {
	return c.TLSContextDial
}

type TLSContext struct {
	context.Context
}

func NewXTransport() *XTransport {
	xTransport := XTransport{
		keepAlive:                	DefaultKeepAlive,
		timeout:                  	DefaultTimeout,
		tlsDisableSessionTickets: 	false,
	}
	defaultCipherSuitesTLS13()
	dlog.Debugf("default CipherSuites=%v", varDefaultCipherSuitesTLS13)
	varDefaultCipherSuitesTLS13 = []uint16{TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
	dlog.Debugf("init CipherSuites=%v", varDefaultCipherSuitesTLS13)
	return &xTransport
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
	if xTransport.Transport == nil {
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
		transport.DialTLSContext = func(ctx context.Context, netw, addr string) (net.Conn, error) {
		fCounter := 0
		Dial:
			name, c, err := ctx.Value(nil).(TLSContextDial)(ctx, netw, addr)
			if err != nil {
				if neterr, ok := err.(net.Error); !ok || !neterr.Timeout() {
					if strings.Contains(err.Error(), "forcibly") {
						if fCounter == 0 {
							dlog.Debugf("DialTLSContext encountered: [%s][%v]", *name, err)
							dlog.Debugf("[%s] retry on forcible block", *name)
						}
						fCounter++
						if fCounter < 1000 {
							goto Dial
						} else {
							dlog.Warnf("[%s] forcible block is willfully activated, see next debug log for last error", *name)
						}
					}
					dlog.Debugf("DialTLSContext encountered: [%s][%v]", *name, err)
				}
				return nil, err
			}
			return c, c.(*tls.Conn).Handshake()
		}
		xTransport.Transport = transport
	}
	th := &TransportHolding{
		Name:       &server.name,
		DomainName: domain,
		SNIShadow:  stamp.SNIShadow,
		SNIBlotUp:  stamp.SNIBlotUp,
	}
	th.IPs = &atomic.Value{}
	th.IPs.Store(epring)
	th.Config = th.buildTLS(xTransport)
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
	th.IPs = &atomic.Value{}
	th.IPs.Store(epring)
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
		NextProtos: []string{"h2"},
	}
	if !xTransport.tlsDisableSessionTickets {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	}
	cfg.PreferServerCipherSuites = false
	cfg.CipherSuites = varDefaultCipherSuitesTLS13
	cfg.ServerName = th.DomainName
	if cfg.InsecureSkipVerify {
		dlog.Debugf("SNI setup for [%s]", *th.Name)
		switch th.SNIBlotUp {
			case stamps.SNIBlotUpTypeOmit:    cfg.ServerName = ""
			case stamps.SNIBlotUpTypeIPAddr:  cfg.ServerName = th.IPs.Load().(*EPRing).IP.String()
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
	alive := xTransport.keepAlive
	cfg := th.Config
	th.Context = &HTTPSContext{Context:context.Background(),}
	th.Context.TLSContextDial = func(ctx context.Context, netw, addr string) (*string, net.Conn, error) {
		if xTransport.Proxies != nil {
			if plainConn, err := xTransport.Proxies.GetDialContext()(ctx, netw, addr); err == nil {
				return th.Name, tls.Client(plainConn, cfg), nil
			} else {
				return th.Name, nil, err
			}
		}
		if strings.HasSuffix(addr, th.DomainName) {
			dlog.Criticalf("mismatch addr for TransportHolding(%s): [%s]", th.Name, addr)
			return th.Name, nil, errors.New("mismatch TransportHolding")
		}
		epring := th.IPs.Load().(*EPRing)
		addr = epring.String()
		th.IPs.Store(epring.Next())
		if dialer, err := GetDialer("tcp", xTransport.LocalInterface, 2000*time.Millisecond, alive); err != nil {
			return th.Name, nil, err
		} else {
			conn, err := tls.DialWithDialer(dialer, netw, addr, cfg)
			return th.Name, conn, err
		}
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
	proto := "tcp"
	goto Go
Error:
	return nil, err
Go:
	if timeout <= 0 {
		timeout = xTransport.timeout
	}
	proxies := xTransport.Proxies.Merge(th.Proxies)
	if proxies == nil {
		conn, err = Dial(proto, th.IPs.Load().(*EPRing).String(), xTransport.LocalInterface, timeout, xTransport.keepAlive, ctx)
	} else {
		conn, err = xTransport.Proxies.GetDialContext()(ctx, "tcp", th.IPs.Load().(*EPRing).String())
	}
	if err != nil {
		goto Error
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		goto Error
	}
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
	client := http.Client{Transport: xTransport.Transport, Timeout: timeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},}
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
	if ctx == nil {
		ctx = th.Context
	}
	req = req.WithContext(ctx)
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
	}
	if err != nil {
		dlog.Debugf("request error-[%s]", err)
		if strings.Contains(err.Error(), "handshake failure") {
			dlog.Error("HTTPS handshake failure")
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

