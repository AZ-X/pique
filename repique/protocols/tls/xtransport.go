package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
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
	stamps "github.com/AZ-X/pique/repique/unclassified/stammel"
)

const (
	GET                          = "GET"
	POST                         = "POST"
	DOHMediaType                 = "application/dns-message"
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
	IPs                             interface{} //*EPRing
	Name                            *string //redundant key: name of stamp for now
	DomainName                      string
	SNIShadow                       string
	SNIBlotUp                       stamps.SNIBlotUpType
	Proxies                         *conceptions.NestedProxy // individual proxies chain
	DefaultContext                  context.Context //TLSContext or HTTPSContext
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

func NewXTransport() *XTransport {
	XTransport := XTransport{
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
			name, c, err := ctx.Value(nil).(common.TLSContextDial)(ctx, netw, addr)
			if err != nil {
					if neterr, ok := err.(net.Error); !ok || !neterr.Timeout() {
						dlog.Debugf("DialTLSContext encountered: [%s][%v]", *name, err)
					}
					return nil, err
			}
			return c, nil // in case dialConn do Handshake there
		}
		XTransport.Transport = transport
	}
	if err := XTransport.BuildTLS(server, true); err != nil {
		return err
	}
	return nil
}

func (XTransport *XTransport) BuildTLS(server common.RegisteredServer, https bool) error {
	dlog.Debugf("building TLS for [%s]", server.Name)
	stamp := server.Stamp
	domain, port, err := common.ExtractHostAndPort(stamp.ProviderName, stamps.DefaultPort)
	if err != nil {
		return err
	}
	var endpoints []*common.Endpoint
	for _, addr := range strings.Split(stamp.ServerAddrStr, common.Delimiter) {
		endpoint, err := common.ResolveEndpoint(addr)
		if err != nil {
			return err
		}
		if endpoint.Port != 0 && endpoint.Port != stamps.DefaultPort {
			port = endpoint.Port
		}
		endpoint.Port = port
		endpoints = append(endpoints, endpoint)
	}
	th := &TransportHolding{
		Name:       &server.Name,
		DomainName: domain,
		SNIShadow:  stamp.SNIShadow,
		SNIBlotUp:  stamp.SNIBlotUp,
	}
	var ip string
	if len(endpoints) > 1 {
		epring := common.LinkEPRing(endpoints...)
		ip = epring.IP.String()
		th.IPs = &atomic.Value{}
		th.IPs.(*atomic.Value).Store(epring)
	} else {
		th.IPs = endpoints[0].String()
		ip = endpoints[0].IP.String()
	}
	th.Config = th.BuildTLS(XTransport, ip)
	if err := th.BuildTransport(XTransport, XTransport.Proxies, https); err != nil {
		return err
	}
	XTransport.Transports[server.Name] = th
	return nil
}

const (
	CurveCECPQ2 tls.CurveID = 16696
	goose = "google"
)

func (th *TransportHolding) BuildTLS(XTransport *XTransport, ip string) (cfg *tls.Config) {
	cid := tls.X25519
	if strings.Contains(th.DomainName, goose) {
		cid = CurveCECPQ2 // fixed one; we do NOT make choice or expose the capability
	}
	cfg = &tls.Config{
		SessionTicketsDisabled: XTransport.TlsDisableSessionTickets,
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{cid},
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
			case stamps.SNIBlotUpTypeIPAddr:  cfg.ServerName = ip
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
				opts.DNSName = th.DomainName //in case of booby SNIShadow 
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
			}
			return nil
		}
	}
	return cfg
}

func (th *TransportHolding) BuildTransport(XTransport *XTransport, proxies *conceptions.NestedProxy, https bool) error {
	alive := XTransport.KeepAlive
	cfg := th.Config
	df := func(ctx context.Context, netw, addr string) (*string, net.Conn, error) {
		if proxies != nil {
			if plainConn, err := proxies.GetDialContext()(ctx, XTransport.LocalInterface, netw, addr); err == nil {
				return th.Name, tls.Client(plainConn, cfg), nil
			} else {
				return th.Name, nil, err
			}
		}
		if !strings.HasPrefix(addr, th.DomainName) {
			panic(dlog.Errorf("mismatch addr for TransportHolding(%s): [%s]", th.Name, addr))
		}
		if str, ok := th.IPs.(string); ok {
			addr = str
		} else {
			epring := th.IPs.(*atomic.Value).Load().(*common.EPRing)
			addr = epring.String()
			th.IPs.(*atomic.Value).Store(epring.Next())
		}

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
	if https {
		th.DefaultContext = &common.HTTPSContext{TLSContext:&common.TLSContext{Context:context.Background(), TLSContextDial:df,}, Tag:th.Name, }
	} else {
		th.DefaultContext = &common.TLSContext{Context:context.Background(), TLSContextDial:df,}
	}
	return nil
}

const parallel_dial_total = 5

type _TLSConn interface {
	net.Conn
	Handshake() error
	ConnectionState() tls.ConnectionState
}

// I don't foresee any benefit from dtls, so let's wait for DNS over QUIC 
func (XTransport *XTransport) FetchDoT(name string, serverProto string, ctx context.Context, body *[]byte, Timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	th, found := XTransport.Transports[name]
	if !found {
		panic(name + " not found for Transports")
		return nil, errors.New("name not found for Transports")
	}
	return XTransport.fetchDoT(th, serverProto, ctx, body, Timeout, cbs...)
}

func (XTransport *XTransport) fetchDoT(th *TransportHolding, _ string, ctx context.Context, msg *[]byte, Timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	const proto = "tcp"
	if Timeout <= 0 {
		Timeout = XTransport.Timeout
	}
	var conn net.Conn
	if ctx == nil {
		ctx = th.DefaultContext
	}
	if tslCtx, ok := ctx.(*common.TLSContext); ok {
		_, conn, err = tslCtx.TLSContextDial(tslCtx.Context, proto, th.DomainName)
	} else {
		_, conn, err = th.DefaultContext.(*common.TLSContext).TLSContextDial(ctx, proto, th.DomainName)
	}

	if err != nil {
		goto Error
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(Timeout)); err != nil {
		goto Error
	}
	tlsConn := conn.(_TLSConn)
	if err = tlsConn.Handshake(); err != nil {
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
	var response []byte
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

func (XTransport *XTransport) FetchHTTPS(name string, path string, method string, doh bool, ctx context.Context, body *[]byte, Timeout time.Duration, cbs ...interface{}) ([]byte, error) {
	th, found := XTransport.Transports[name]
	if !found {
		panic(name + "name not found for Transports")
		return nil, errors.New("name not found for Transports")
	}
	return XTransport.fetchHTTPS(th, path, method, doh, ctx, body, Timeout, cbs...)
}

func (XTransport *XTransport) fetchHTTPS(th *TransportHolding, path string, method string, doh bool, ctx context.Context, body *[]byte, Timeout time.Duration, cbs ...interface{}) ([]byte, error) {
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
		ctx = th.DefaultContext
	} else if _, ok := ctx.(*common.HTTPSContext); !ok {
		ctx = th.DefaultContext.(*common.HTTPSContext).WithContext(ctx)
	} 
	req = req.WithContext(ctx)
	if method == "POST" && body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
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
	bin, err := io.ReadAll(io.LimitReader(resp.Body, size))
	if err != nil {
		goto Error
	}
	resp.Body.Close()
	return bin, nil
}

func (XTransport *XTransport) Get(name string, path string, ctx context.Context, Timeout time.Duration) ([]byte, error) {
	return XTransport.FetchHTTPS(name, path, GET, false, ctx, nil, Timeout)
}

func (XTransport *XTransport) Post(name string, path string, ctx context.Context, body *[]byte, Timeout time.Duration) ([]byte, error) {
	return XTransport.FetchHTTPS(name, path, POST, false, ctx, body, Timeout)
}

