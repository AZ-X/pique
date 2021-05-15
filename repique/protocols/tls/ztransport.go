package tls

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/AZ-X/pique/repique/protocols"
	stamps "github.com/AZ-X/pique/repique/unclassified/stammel"

	"github.com/jedisct1/dlog"
)

type HttpMethod uint8
const (
	GET                          = HttpMethod(0)
	POST                         = HttpMethod(1)
	HTTPGET                      = "GET"
	HTTPPOST                     = "POST"
	DOHMediaType                 = "application/dns-message"
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


type PinningError struct {
	name string
}

func (e *PinningError) Error() string {
	return "unmatched certificate pin for " + e.name
}


//to reduce memory payload, shift http's Transport and ensure single instance of it
//now give up calling CloseIdleConnections method which has side effect on burst connections with different cm
//since we use custom dial on Transport with variant of tls config, have to cover all the proxies usage
//upon TLS
type TLSMeta struct {
	*protocols.NetworkBase
	*tls.Config
	IPs                             interface{} //*EPRing
	Name                            *string //redundant key: name of stamp for now
	DomainName                      string
	SNIShadow                       string
	SNIBlotUp                       stamps.SNIBlotUpType
	Pinnings                        [][]byte
	DefaultContext                  context.Context //TLSContext or HTTPSContext
}

func InitTLS13() {
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
}

func NewZTransport(alive time.Duration, timeout time.Duration) (t *http.Transport) {
	t = &http.Transport{
		ForceAttemptHTTP2:      true,//formal servers (DOH, DOT, https-gits, etc.) should provide H>1.1 infrastructure with tls>1.2
		DisableKeepAlives:      alive < 0,
		//DisableKeepAlives:    true,   // in case some of horrible issues inside stdlib :)
		DisableCompression:     true,
		MaxIdleConns:           5,
		MaxConnsPerHost:        0,
		TLSHandshakeTimeout:    1500 * time.Millisecond,
		IdleConnTimeout:        alive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
	}
	t.DialTLSContext = func(ctx context.Context, netw, addr string) (net.Conn, error) {
		name, c, err := ctx.Value(nil).(common.TLSContextDial)(ctx, netw, addr)
		if err != nil {
				if neterr, ok := err.(net.Error); !ok || !neterr.Timeout() {
					dlog.Debugf("DialTLSContext encountered: [%s][%v]", *name, err)
				}
				return nil, err
		}
		return c, nil // in case dialConn do Handshake there
	}
	return
}

func NewTLSMeta(server *common.RegisteredServer, network *protocols.NetworkBase, disableTLSSession bool) *TLSMeta {
	if m, err := newTLSMeta(server, network, disableTLSSession); err == nil {
		return m
	} else {
		panic(err)
	}
}

func newTLSMeta(server *common.RegisteredServer, network *protocols.NetworkBase, disableTLSSession bool) (*TLSMeta, error) {
	dlog.Debugf("building TLS Meta for [%s]", server.Name)
	stamp := server.Stamp
	https := stamp.Proto.String() == "DoH"
	defaultPort := stamps.DefaultPort
	if !https {
		defaultPort = DoTDefaultPort
	}
	domain, port, err := common.ExtractHostAndPort(stamp.ProviderName, defaultPort)
	if err != nil {
		return nil, err
	}
	name := server.Name
	hashes := make([][]byte, len(stamp.Hashes))
	for idx, hash := range stamp.Hashes {
		hashes[idx] = make([]byte, len(hash))
		copy(hashes[idx], hash)
	}
	sm := &TLSMeta{
		Name:        &name,
		NetworkBase: network,
		DomainName:  domain,
		Pinnings:    hashes,
		SNIShadow:   stamp.SNIShadow,
		SNIBlotUp:   stamp.SNIBlotUp,
	}
	var ip string
	if len(stamp.ServerAddrStr) > 0 {
		var endpoints []*common.Endpoint
		for _, addr := range strings.Split(stamp.ServerAddrStr, common.Delimiter) {
			endpoint, err := common.ResolveEndpoint(addr)
			if err != nil {
				return nil, err
			}
			if endpoint.Port != 0 && endpoint.Port != defaultPort {
				port = endpoint.Port
			}
			endpoint.Port = port
			endpoints = append(endpoints, endpoint)
		}
		if len(endpoints) > 1 {
			epring := common.LinkEPRing(endpoints...)
			ip = epring.IP.String()
			sm.IPs = &atomic.Value{}
			sm.IPs.(*atomic.Value).Store(epring)
		} else {
			sm.IPs = endpoints[0].String()
			ip = endpoints[0].IP.String()
		}
	} else if sm.SNIBlotUp == stamps.SNIBlotUpTypeIPAddr {
		panic("unsupported IP SNI BlotUp when bootstrapping")
	}
	sm.Config = sm.configTLS(disableTLSSession, ip)
	if err := sm.adaptContext(https); err != nil {
		return nil, err
	}
	return sm, nil
}

func (sm *TLSMeta) configTLS(disableTLSSession bool, ip string) (cfg *tls.Config) {
	cid := tls.X25519
	cfg = &tls.Config{
		SessionTicketsDisabled: disableTLSSession,
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{cid},
		DynamicRecordSizingDisabled: true,
		InsecureSkipVerify: sm.SNIBlotUp != stamps.SNIBlotUpTypeDefault,
		NextProtos: []string{"h2"},
	}
	if !disableTLSSession {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	}
	cfg.PreferServerCipherSuites = false
	cfg.CipherSuites = varDefaultCipherSuitesTLS13
	cfg.ServerName = sm.DomainName
	verifyPin := func(cs *tls.ConnectionState) error {
		pc := make([]*x509.Certificate, len(cs.PeerCertificates))
		copy(pc, cs.PeerCertificates)
		RowLoop:
		for _, pinning := range sm.Pinnings {
			for idx, cert := range pc {
				h := sha256.Sum256(cert.RawTBSCertificate)
				if bytes.Equal(pinning, h[:]) {
					pc = append(pc[:idx], pc[idx+1:]...)
					continue RowLoop
				}
			}
			for _, pinning1 := range sm.Pinnings {
				dlog.Debugf("tbs=[%x] %s", pinning1, *sm.Name)
			}
			for _, cert := range cs.PeerCertificates {
				h := sha256.Sum256(cert.RawTBSCertificate)
				dlog.Debugf("unmatched cert: [%s] tbs=[%x] %s",cert.Subject, h, *sm.Name)
			}
			return &PinningError{name:*sm.Name}
		}
		return nil
	}
	if cfg.InsecureSkipVerify {
		dlog.Debugf("SNI setup for [%s]", *sm.Name)
		switch sm.SNIBlotUp {
			case stamps.SNIBlotUpTypeOmit:    cfg.ServerName = ""
			case stamps.SNIBlotUpTypeIPAddr:  cfg.ServerName = ip
			case stamps.SNIBlotUpTypeMoniker: cfg.ServerName = sm.SNIShadow
		}
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				Roots:         cfg.RootCAs,
				DNSName:       sm.SNIShadow, //SNIShadow must be a known trusted alias of the host
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			if err != nil {
				opts.DNSName = sm.DomainName //in case of booby SNIShadow 
				_, err := cs.PeerCertificates[0].Verify(opts)
				if err != nil {
					switch err := err.(type) {
					case x509.CertificateInvalidError:
						return dlog.Errorf("[%v][%v(%v)]:%v", *sm.Name, err.Cert.Subject, err.Cert.NotAfter, err)
					case x509.HostnameError:
						return dlog.Errorf("[%v]%v", *sm.Name, err)
					case x509.UnknownAuthorityError, x509.SystemRootsError:
						return err
					}
				}
			}
			if len(sm.Pinnings) > 0 {
				return verifyPin(&cs)
			}
			return nil
		}
	} else if len(sm.Pinnings) > 0 {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			return verifyPin(&cs)
		}
	}
	return cfg
}

func (sm *TLSMeta) adaptContext(https bool) error {
	cfg := sm.Config
	df := func(ctx context.Context, netw, addr string) (*string, net.Conn, error) {
		if sm.Proxies != nil && sm.Proxies.HasValue() {
			if plainConn, err := sm.Proxies.GetDialContext()(ctx, sm.IFI, netw, addr); err == nil {
				return sm.Name, tls.Client(plainConn, cfg), nil
			} else {
				return sm.Name, nil, err
			}
		}
		if !strings.HasPrefix(addr, sm.DomainName) {
			panic(dlog.Errorf("mismatch addr for TLSMeta(%s): [%s]", sm.Name, addr))
		}
		if str, ok := sm.IPs.(string); ok {
			addr = str
		} else {
			epring := sm.IPs.(*atomic.Value).Load().(*common.EPRing)
			addr = epring.String()
			sm.IPs.(*atomic.Value).Store(epring.Next())
		}

		if dialer, err := common.GetDialer("tcp", sm.IFI, 800*time.Millisecond, sm.Alive); err != nil {
			return sm.Name, nil, err
		} else {
			var conn net.Conn
			var err error
			if conn, err = common.ParallelDialWithDialer(ctx, dialer, netw, addr, 2); err != nil {
				dialer.Timeout *= 2
				conn, err = common.ParallelDialWithDialer(ctx, &tls.Dialer{NetDialer:dialer, Config:cfg}, netw, addr, parallel_dial_total)
				return sm.Name, conn, err
			}
			return sm.Name, tls.Client(conn, cfg), nil
		}
	}
	if https {
		sm.DefaultContext = &common.HTTPSContext{TLSContext:&common.TLSContext{Context:context.Background(), TLSContextDial:df,}, Tag:sm.Name, }
	} else {
		sm.DefaultContext = &common.TLSContext{Context:context.Background(), TLSContextDial:df,}
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
func (sm *TLSMeta) FetchDoT(_ string, ctx context.Context, msg *[]byte, timeout time.Duration, cbs ...interface{}) (*[]byte, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	const proto = "tcp"
	if timeout <= 0 {
		timeout = sm.Timeout
	}
	var conn net.Conn
	if ctx == nil {
		ctx = sm.DefaultContext
	}
	if tslCtx, ok := ctx.(*common.TLSContext); ok {
		_, conn, err = tslCtx.TLSContextDial(tslCtx.Context, proto, sm.DomainName)
	} else {
		_, conn, err = sm.DefaultContext.(*common.TLSContext).TLSContextDial(ctx, proto, sm.DomainName)
	}

	if err != nil {
		goto Error
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
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
		common.Program_dbg_full_log("retry on timeout or <-EOF msg")
	}
	if err != nil {
		common.Program_dbg_full_log("FetchDoT E02")
		goto Error
	}

	return &response, nil
}

func (sm *TLSMeta) FetchHTTPS(trans *http.Transport, domain, path *string, method HttpMethod, doh bool, ctx context.Context, body *[]byte, timeout time.Duration, cbs ...interface{}) (*[]byte, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	if timeout <= 0 {
		timeout = sm.Timeout
	}
	client := http.Client{Transport: trans, Timeout: timeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},}
	// User-Agent. If set to nil or empty string, then omit it. Otherwise if not mentioned, include the default.
	header := map[string][]string{"User-Agent": {""}}
	if domain == nil {
		domain = &sm.DomainName
	}
	url := &url.URL{
		Scheme: "https",
		Host:   *domain,
		Path:   *path,
	}
	if doh {
		header["accept"] = []string{DOHMediaType}
		if method == POST {
			header["content-type"] = []string{DOHMediaType}
		} else if method == GET {
			qs := url.Query()
			//rfc8484 single variable "dns" is defined as the content of the DNS request
			encBody := base64.RawURLEncoding.EncodeToString(*body)
			qs.Add("dns", encBody)
			url.RawQuery = qs.Encode()
		}
	}

	//rfc8484
	//The URI Template defined in this document is processed without any variables when the HTTP method is POST
	//Who uses body_hash?

	req := &http.Request{
		URL:    url,
		Header: header,
		Close:  trans.DisableKeepAlives,
	}
	switch method {
		case GET:  req.Method = HTTPGET
		case POST: req.Method = HTTPPOST
	}

	if ctx == nil {
		ctx = sm.DefaultContext
	} else if _, ok := ctx.(*common.HTTPSContext); !ok {
		ctx = sm.DefaultContext.(*common.HTTPSContext).WithContext(ctx)
	} 
	req = req.WithContext(ctx)
	if method == POST && body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}
	resp, err := client.Do(req)
	if err != nil {
		common.Program_dbg_full_log("request error-[%s]", err)
	}
	if resp == nil {
		if err == nil {
			err = errors.New("unknown error when fetching https, stop using it until root cause has been found")
		}
	} else {
		for _, cb := range cbs {
			switch cb := cb.(type) {
				case func(*tls.ConnectionState) error:
					if err1 := cb(resp.TLS); err1 != nil {
						goto Error
					}
				default:
					dlog.Errorf("unhandled callback(T=%T) calling fetchHTTPS", cb)
			}
		}
		if err == nil && resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = errors.New(resp.Status)
		}
	}
	if err != nil {
		goto Error
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
	return &bin, nil
}

func (sm *TLSMeta) Get(trans *http.Transport, domain, path *string, ctx context.Context, timeout time.Duration) (*[]byte, error) {
	return sm.FetchHTTPS(trans, domain, path, GET, false, ctx, nil, timeout)
}

func (sm *TLSMeta) Post(trans *http.Transport, domain, path *string, ctx context.Context, body *[]byte, timeout time.Duration) (*[]byte, error) {
	return sm.FetchHTTPS(trans, domain, path, POST, false, ctx, body, timeout)
}
