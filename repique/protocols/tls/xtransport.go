package tls

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
	
	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/conceptions"
	"github.com/jedisct1/dlog"
	stamps "stammel"
)

const (
	GET                          = "GET"
	POST                         = "POST"
	DOHMediaType                 = "application/dns-message"
	DefaultKeepAlive             = 0 * time.Second
	DefaultTimeout               = 30 * time.Second
	DoTDefaultPort               = 853
	MaxHTTPBodyLength            = 4000000
	TLS_AES_128_GCM_SHA256       = 0x1301 // 16bytes key
	TLS_AES_256_GCM_SHA384       = 0x1302 // 1st not pq ready
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303 // 2nd not pq ready
)

var (
//go:linkname varDefaultCipherSuitesTLS13 crypto/tls.varDefaultCipherSuitesTLS13
varDefaultCipherSuitesTLS13 []uint16
//go:linkname supportedSignatureAlgorithms crypto/tls.supportedSignatureAlgorithms
supportedSignatureAlgorithms []tls.SignatureScheme
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
	Proxies                         *conceptions.NestedProxy // individual proxies chain
}

//upon TLS
type XTransport struct {
	*http.Transport
	Transports                      map[string]*TransportHolding //key: name of stamp for now
	KeepAlive                       time.Duration
	Timeout                         time.Duration
	TlsDisableSessionTickets        bool
	Proxies                         *conceptions.NestedProxy
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

func NewXTransport() *XTransport {
	XTransport := XTransport{
		KeepAlive:                	DefaultKeepAlive,
		Timeout:                  	DefaultTimeout,
		TlsDisableSessionTickets: 	false,
	}
	defaultCipherSuitesTLS13()
	dlog.Debugf("default CipherSuites=%v", varDefaultCipherSuitesTLS13)
	varDefaultCipherSuitesTLS13 = []uint16{TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
	dlog.Debugf("init CipherSuites=%v", varDefaultCipherSuitesTLS13)
	dlog.Debugf("default SignatureAlgorithms=%v", supportedSignatureAlgorithms)
	supportedSignatureAlgorithms = []tls.SignatureScheme{
	tls.Ed25519,
	tls.ECDSAWithP256AndSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.ECDSAWithP521AndSHA512,
	tls.PSSWithSHA384,
	tls.PSSWithSHA512,
	}
	dlog.Debugf("init SignatureAlgorithms=%v", supportedSignatureAlgorithms)

	return &XTransport
}


//general template for all TLS conn;
func (XTransport *XTransport) BuildTransport(server common.RegisteredServer, _ *conceptions.NestedProxy) error {
	dlog.Debugf("building transport for [%s]", server.Name)
	Timeout := XTransport.Timeout
	stamp := server.Stamp
	domain, port, err := common.ExtractHostAndPort(stamp.ProviderName, stamps.DefaultPort)
	if err != nil {
		return err
	}
	endpoint, err := common.ResolveEndpoint(stamp.ServerAddrStr)
	if err != nil {
		return err
	}
	if endpoint.Port != 0 && endpoint.Port != stamps.DefaultPort {
		port = endpoint.Port
	}
	endpoint.Port = port
	epring := common.LinkEPRing(endpoint)
	if XTransport.Transport == nil {
		transport := &http.Transport{
		ForceAttemptHTTP2:      true,//formal servers (DOH, DOT, https-gits, etc.) should provide H>1.1 infrastructure with tls>1.2
		DisableKeepAlives:      XTransport.KeepAlive < 0,
		//DisableKeepAlives:    true,   // in case some of horrible issues inside stdlib :)
		DisableCompression:     true,
		MaxIdleConns:           5,
		MaxConnsPerHost:        0,
		TLSHandshakeTimeout:    1500 * time.Millisecond,
		IdleConnTimeout:        XTransport.KeepAlive,
		ResponseHeaderTimeout:  Timeout,
		ExpectContinueTimeout:  Timeout,
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
			return c, nil // in case dialConn do Handshake there
		}
		XTransport.Transport = transport
	}
	th := &TransportHolding{
		Name:       &server.Name,
		DomainName: domain,
		SNIShadow:  stamp.SNIShadow,
		SNIBlotUp:  stamp.SNIBlotUp,
	}
	th.IPs = &atomic.Value{}
	th.IPs.Store(epring)
	th.Config = th.BuildTLS(XTransport)
	if err := th.BuildTransport(XTransport, XTransport.Proxies); err != nil {
		return err
	}
	XTransport.Transports[server.Name] = th
	return nil
}

func (XTransport *XTransport) BuildTLS(server common.RegisteredServer) error {
	dlog.Debugf("building TLS for [%s]", server.Name)
	stamp := server.Stamp
	domain, port, err := common.ExtractHostAndPort(stamp.ProviderName, DoTDefaultPort)
	if err != nil {
		return err
	}
	endpoint, err := common.ResolveEndpoint(stamp.ServerAddrStr)
	if err != nil {
		return err
	}
	if endpoint.Port != 0 && endpoint.Port != DoTDefaultPort {
		port = endpoint.Port
	}
	endpoint.Port = port
	epring := common.LinkEPRing(endpoint)
	th := &TransportHolding{
		Name:       &server.Name,
		DomainName: domain,
		SNIShadow:  stamp.SNIShadow,
		SNIBlotUp:  stamp.SNIBlotUp,
	}
	th.IPs = &atomic.Value{}
	th.IPs.Store(epring)
	th.Config = th.BuildTLS(XTransport)
	XTransport.Transports[server.Name] = th
	return nil
}

func (th *TransportHolding) BuildTLS(XTransport *XTransport) (cfg *tls.Config) {
	cfg = &tls.Config{
		SessionTicketsDisabled: XTransport.TlsDisableSessionTickets,
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		DynamicRecordSizingDisabled: true,
		InsecureSkipVerify: th.SNIBlotUp != stamps.SNIBlotUpTypeDefault,
		NextProtos: []string{"h2"},
	}
	if !XTransport.TlsDisableSessionTickets {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	}
	cfg.PreferServerCipherSuites = false
	cfg.CipherSuites = varDefaultCipherSuitesTLS13
	cfg.ServerName = th.DomainName
	if cfg.InsecureSkipVerify {
		dlog.Debugf("SNI setup for [%s]", *th.Name)
		switch th.SNIBlotUp {
			case stamps.SNIBlotUpTypeOmit:    cfg.ServerName = ""
			case stamps.SNIBlotUpTypeIPAddr:  cfg.ServerName = th.IPs.Load().(*common.EPRing).IP.String()
			case stamps.SNIBlotUpTypeMoniker: cfg.ServerName = th.SNIShadow
		}
		cfg.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
			if len(certificates) < 2 {
				return errors.New("VerifyPeerCertificate: invaild certificates chain")
			}
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
			
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			if err != nil {
				switch err := err.(type) {
				case x509.CertificateInvalidError:
					return dlog.Errorf("[%v][%v(%v)]:%v", *th.Name, err.Cert.Subject, err.Cert.NotAfter, err)
				case x509.HostnameError:
					return dlog.Errorf("[%v]%v", *th.Name, err)
				case x509.UnknownAuthorityError, x509.SystemRootsError:
					return err
				}
			}
			return nil
		}
	}
	return cfg
}

func (th *TransportHolding) BuildTransport(XTransport *XTransport, proxies *conceptions.NestedProxy) error {
	alive := XTransport.KeepAlive
	cfg := th.Config
	th.Context = &HTTPSContext{Context:context.Background(),}
	th.Context.TLSContextDial = func(ctx context.Context, netw, addr string) (*string, net.Conn, error) {
		if XTransport.Proxies != nil {
			if plainConn, err := XTransport.Proxies.GetDialContext()(ctx, XTransport.LocalInterface, netw, addr); err == nil {
				return th.Name, tls.Client(plainConn, cfg), nil
			} else {
				return th.Name, nil, err
			}
		}
		if !strings.HasPrefix(addr, th.DomainName) {
			panic(dlog.Errorf("mismatch addr for TransportHolding(%s): [%s]", th.Name, addr))
		}
		epring := th.IPs.Load().(*common.EPRing)
		addr = epring.String()
		th.IPs.Store(epring.Next())
		if dialer, err := common.GetDialer("tcp", XTransport.LocalInterface, 800*time.Millisecond, alive); err != nil {
			return th.Name, nil, err
		} else {
			var conn net.Conn
			var err error
			if conn, err = common.ParallelDialWithDialer(ctx, dialer, netw, addr, 2); err != nil {
				dialer.Timeout *= 2
				conn, err = common.ParallelDialWithDialer(ctx, &tls.Dialer{NetDialer:dialer, Config:cfg}, netw, addr, parallel_dial_total)
				return th.Name, conn, err
			}
			return th.Name, tls.Client(conn, cfg), nil
		}
	}
	return nil
}

const parallel_dial_total = 5


// I don't foresee any benefit from dtls, so let's wait for DNS over QUIC 
func (XTransport *XTransport) FetchDoT(name string, serverProto string, ctx *common.TLSContext, body *[]byte, Timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	th, found := XTransport.Transports[name]
	if !found {
		panic(name + " not found for Transports")
		return nil, errors.New("name not found for Transports")
	}
	return XTransport.fetchDoT(th, serverProto, ctx, body, Timeout, cbs...)
}

func (XTransport *XTransport) fetchDoT(th *TransportHolding, _ string, ctx *common.TLSContext, msg *[]byte, Timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	var err error
	var conn net.Conn
	var response []byte
	proto := "tcp"
	goto Go
Error:
	return nil, err
Go:
	if Timeout <= 0 {
		Timeout = XTransport.Timeout
	}
	proxies := XTransport.Proxies.Merge(th.Proxies)
	if proxies == nil {
		conn, err = common.Dial(proto, th.IPs.Load().(*common.EPRing).String(), XTransport.LocalInterface, Timeout, XTransport.KeepAlive, ctx)
	} else {
		conn, err = XTransport.Proxies.GetDialContext()(ctx, XTransport.LocalInterface, "tcp", th.IPs.Load().(*common.EPRing).String())
	}
	if err != nil {
		goto Error
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(Timeout)); err != nil {
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
		if err = common.WriteDP(tlsConn, *msg); err != nil {
			common.Program_dbg_full_log("FetchDoT E01")
			continue
		}
		if response, err = common.ReadDP(tlsConn); err == nil {
			break
		}
		common.Program_dbg_full_log("retry on Timeout or <-EOF msg")
	}
	if err != nil {
		common.Program_dbg_full_log("FetchDoT E02")
		goto Error
	}

	return response, nil
}


func (XTransport *XTransport) FetchHTTPS(name string, path string, method string, doh bool, ctx *HTTPSContext, body *[]byte, Timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	th, found := XTransport.Transports[name]
	if !found {
		panic(name + "name not found for Transports")
		return nil, errors.New("name not found for Transports")
	}
	return XTransport.fetchHTTPS(th, path, method, doh, ctx, body, Timeout, cbs...)
}

func (XTransport *XTransport) fetchHTTPS(th *TransportHolding, path string, method string, doh bool, ctx *HTTPSContext, body *[]byte, Timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	if Timeout <= 0 {
		Timeout = XTransport.Timeout
	}
	client := http.Client{Transport: XTransport.Transport, Timeout: Timeout,
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
		Close:  XTransport.KeepAlive < 0,
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
		common.Program_dbg_full_log("request error-[%s]", err)
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
		size = common.Min64(resp.ContentLength, size)
	}
	bin, err := ioutil.ReadAll(io.LimitReader(resp.Body, size))
	if err != nil {
		goto Error
	}
	resp.Body.Close()
	return bin, nil
}

func (XTransport *XTransport) Get(name string, path string, ctx *HTTPSContext, Timeout time.Duration) ([]byte, error) {
	return XTransport.FetchHTTPS(name, path, GET, false, ctx, nil, Timeout)
}

func (XTransport *XTransport) Post(name string, path string, ctx *HTTPSContext, body *[]byte, Timeout time.Duration) ([]byte, error) {
	return XTransport.FetchHTTPS(name, path, POST, false, ctx, body, Timeout)
}

