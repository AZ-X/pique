package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
	"encoding/binary"
	"hash/maphash"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "unsafe"

	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/services"
	"github.com/AZ-X/pique/repique/conceptions"
	"github.com/AZ-X/pique/repique/behaviors"
	
	"github.com/jedisct1/dlog"
	"github.com/AZ-X/dns"
)

const (
	RF                  = "RF"
	NX                  = "NX"
	NC                  = "NC"
	PL                  = "PL"
	AS                  = "AS"
)

type clockEntry struct {
	*atomic.Value //*common.EPRing
	rf, nx, nc            bool
	pll, plh              *int
}

type inCacheResponse struct {
	*dns.Msg
	expiration time.Time
}

type Error_CP_Reason Error
func (e *Error_CP_Reason) Error() string {
	return e.Ex
}

func (e *Error_CP_Reason) CPCNAMEExplication() *Error_CP_Reason {
	e.Ex = "black_cloaking_routine matches CNAME: " + e.Ex
	return e
}

// caches and patterns; unitized handling
type CP struct {
	*Config
	f              FChannelByName
	actions        *services.Regex_Actions
	clock_cache    *conceptions.CloakCache
	cache          *conceptions.Cache
	startup        *sync.Once
	pll, plh       *int
	preloadings    []*string //domains
	true, false    bool
}

func (cp *CP) Name() string {
	return Channel_CP
}

func (cp *CP) Init(cfg *Config, f FChannelByName) {
	cp.true, cp.false = true, false
	cp.Config = cfg
	cp.f = f
	cp._init(false)
	if cp.BlackCloaking != nil && cp.BlackCloakingMon != nil && *cp.BlackCloakingMon {
		dlog.Infof("reg black_cloaking_routine={%s}", *cp.BlackCloaking)
		behaviors.RegisterFswatcher(*cp.BlackCloaking, func(){
			dlog.Infof("reloading black_cloaking_routine={%s}", *cp.BlackCloaking)
			cp._init(true)
		})
	}
}

func (cp *CP) _init(reloading bool) {
	ttl := DefaultTTL
	if cp.BlackCloaking != nil {
		bin, err := os.ReadFile(*cp.BlackCloaking)
		if err != nil {
			panic(err)
		}
		cloaks := make(map[string]map[string][]*common.Endpoint)
		var nxs, rfs []string
		ips := make([]struct{Tag interface{}; Exps []string}, 0)
		dms := make([]struct{Tag interface{}; Exps []string}, 0)
		pls := make(map[string][]*string)
		startup := "#"
		exp := regexp.MustCompile(`(?m)^(?:[ ]*(?P<target>[\w.:\[\]\%]+)[ ]+(?P<patterns>[^ #\n]{1}[^ \r\n]+(?:[ ]+[^ #\n]{1}[^ \r\n]+)*))?[ ]*(?:[ ]+#(?P<comment>[^\r\n]*))?(?:\r)?$|(?:^[ ]*#(?P<commentline>[^\r\n]*)(?:\r)?$)|(?:^(?P<unrecognized>[^\r\n]*)(?:\r)?$)`)
		exp.Longest()
		whitespaces := regexp.MustCompile(`[ ]+`)
		matches := exp.FindAllStringSubmatch(string(bin), -1)
		for line, match := range matches {
			if len(match[exp.SubexpIndex("unrecognized")]) != 0 {
				dlog.Errorf("at line %d, content:%s", line+1, match[exp.SubexpIndex("unrecognized")])
				panic("unrecognized content found in black_cloaking_routine, check it before use")
			}
			if len(match[exp.SubexpIndex("target")]) == 0 {
				continue
			}
			var err error
			var rf, nx, nc, pl, as bool
			var ip *common.Endpoint
			switch match[exp.SubexpIndex("target")] {
			case RF: rf = true
			case NX: nx = true
			case NC: nc = true
			case PL: pl = true
			case AS: as = true
			default: if ip, err = common.ResolveEndpoint(match[exp.SubexpIndex("target")]); err != nil {
					dlog.Errorf("at line %d, err:%v", line+1, err)
					panic("unrecognized ip address found in black_cloaking_routine, check it before use")
					}
			}
			patterns := whitespaces.Split(match[exp.SubexpIndex("patterns")], -1)
			var exps []string
			var pl_name *string
			var pl_domains []*string
			var as_domain *string
			for i, str := range patterns {
				pattern := strings.TrimPrefix(str, `/`)
				if len(pattern) == len(str) {
					if pl {
						pattern := strings.TrimSuffix(pattern, `#`)
						if len(pattern) == len(str) {
							if !dns.IsFqdn(pattern) {
								panic("pattern to PL: only fully qualified domain names are supported ->"+pattern)
							}
							pl_domains = append(pl_domains, &pattern)
						} else {
							pl_name = &pattern
						}
						continue
					}
					cloaking, found := cloaks[pattern]
					if !found {
						cloaking = make(map[string][]*common.Endpoint)
					}
					if rf {
						cloaking["rf"] = nil
					} else if nx {
						cloaking["nx"] = nil
					} else if nc {
						cloaking["nc"] = nil
					} else if as {
						if i != 0 {
							panic("pattern to AS: only REGEX matches are supported")
						}
						if !dns.IsFqdn(pattern) {
								panic("pattern to AS: only fully qualified domain names are supported ->"+pattern)
						}
						as_domain = &pattern
					} else if ip.IP.To4() != nil {
						cloaking["v4"] = append(cloaking["v4"], ip)
					} else {
						cloaking["v6"] = append(cloaking["v6"], ip)
					}
					cloaks[pattern] = cloaking
				} else {
					if rf {
						rfs= append(rfs, pattern)
					} else if nx {
						nxs= append(nxs, pattern)
					} else if nc || pl {
						panic("pattern to NC/PL: only fully qualified domain names are supported")
					} else {
						exps = append(exps, pattern)
					}
				}
			}
			if len(exps) != 0 {
				if as {
					dms = append(dms, struct{Tag interface{}; Exps []string}{as_domain, exps})
				} else {
					ips = append(ips, struct{Tag interface{}; Exps []string}{ip,exps})
				}
			}
			if len(pl_domains) != 0 {
				if pl_name == nil {
					pl_name = &startup
				}
				if entry, ok := pls[*pl_name]; ok {
					pls[*pl_name] = append(entry, pl_domains...)
				} else {
					pls[*pl_name] = pl_domains
				}
			}
		}
		if len(rfs) != 0 || len(nxs) != 0 || len(ips) != 0 || len(dms) != 0 {
			anycast := make([]struct{Tag interface{}; Exps []string}, len(ips) + len(dms))
			copy(anycast, ips)
			copy(anycast[len(ips):], dms)
			cp.actions = services.CreateRegexActions(rfs, nxs, anycast)
		}
		/* for personal use, AMD AES-NI or the Fallback may save a small piece of mem
		preComputeCacheKey := func(qtype uint16, name string) [sha512.Size256]byte {
			var tmp [5]byte
			binary.BigEndian.PutUint16(tmp[0:2], qtype)
			binary.BigEndian.PutUint16(tmp[2:4], dns.ClassINET)
			return *Sum512_256s(tmp[:], []byte(name))
			//h.Sum(sum[:0]) //I don't like keeping writing and summing
		}
		*/
		preComputeCacheKey := func(qtype uint16, name string) uint64 {
			var tmp [5]byte
			binary.BigEndian.PutUint16(tmp[0:2], qtype)
			binary.BigEndian.PutUint16(tmp[2:4], dns.ClassINET)
			var h maphash.Hash
			h.SetSeed(seed)
			h.Write(tmp[:])
			h.Write([]byte(name))
			return h.Sum64()
		}
		if len(cloaks) != 0 || len(pls) != 0 {
			cp.clock_cache = conceptions.NewCloakCache()
			for name,r := range cloaks {
				_, rf := r["rf"]
				_, nx := r["nx"]
				_, nc := r["nc"]
				if rf || nx || nc {
					key := preComputeCacheKey(dns.TypeA, name)
					value := clockEntry{rf:rf, nx:nx, nc:nc}
					cp.clock_cache.Add(key, value)
					if cp.BlockIPv6 != nil && !*cp.BlockIPv6 {
						key = preComputeCacheKey(dns.TypeAAAA, name)
						cp.clock_cache.Add(key, value)
					}
				}
				// always override nx or rf or nc if ip exists 
				if len(r["v4"]) > 0 {
					key := preComputeCacheKey(dns.TypeA, name)
					value := clockEntry{Value:&atomic.Value{},}
					value.Store(common.LinkEPRing(r["v4"]...))
					cp.clock_cache.Add(key, value)
				}
				if len(r["v6"]) > 0 {
					key := preComputeCacheKey(dns.TypeAAAA, name)
					value := clockEntry{Value:&atomic.Value{},}
					value.Store(common.LinkEPRing(r["v6"]...))
					cp.clock_cache.Add(key, value)
				}
			}
			cp.preloadings = nil
			var pll, plh *int = new(int), new(int)
			for name, ds := range pls {
				*pll = *plh
				mistake_proofing := make(map[string]interface{}, len(ds)+1)
				mistake_proofing[name] = nil
				for _, str := range ds {
					key := *str
					if _, found := mistake_proofing[key]; found {
						panic("pattern to PL: check duplicate domains for " + name + " - " + key)
					}
					mistake_proofing[key] = nil
				}
				if name == startup {
					*plh = *pll + len(ds)
					l, h := *pll, *plh
					cp.pll = &l
					cp.plh = &h
					cp.startup = &sync.Once{}
					cp.preloadings = append(cp.preloadings, ds...)
					for _, str := range cp.preloadings[*cp.pll:*cp.plh] {
						common.Program_dbg_full_log("PL startup %s", *str)
					}
				} else {
					if len(ds) < 2 {
						panic("pattern to PL: check domains for " + name)
					}
					*plh = *pll + len(ds) - 1
					l, h := *pll, *plh
					leading := *ds[0]
					key := preComputeCacheKey(dns.TypeA, leading)
					value := clockEntry{pll:&l, plh:&h}
					if cachedAny, ok := cp.clock_cache.Get(key); ok {
						value = cachedAny.(clockEntry)
						value.pll, value.plh = &l, &h
					}
					cp.clock_cache.Add(key, value)
					if cp.BlockIPv6 != nil && !*cp.BlockIPv6 {
						key = preComputeCacheKey(dns.TypeAAAA, leading)
						cp.clock_cache.Add(key, value)
					}
					cp.preloadings = append(cp.preloadings, ds[1:]...)
					for _, str := range cp.preloadings[*value.pll:*value.plh] {
						common.Program_dbg_full_log("PL leading:%s - %s", leading, *str)
					}
				}
			}
			if cp.CloakTTL == nil {
				cp.CloakTTL = &ttl
			}
		} else {
			cp.clock_cache = nil //reloading
		}
	}
	if !reloading && cp.CacheSize != nil {
		size := 1<<math.Ilogb(float64(*cp.CacheSize))
		dlog.Debugf("accurate cache size: %d", size)
		cp.cache = conceptions.NewCache(size)
		if cp.CacheTTL == nil {
			cp.CacheTTL = &ttl
		}
	}
}

/* for personal use, AMD AES-NI or the Fallback may save a small piece of mem

const chunk     = 128
//go:linkname digest crypto/sha512.digest
type digest struct {
	h        [8]uint64
	x        [chunk]byte
	nx       int
	len      uint64
	function crypto.Hash
}

//go:linkname (*digest).checkSum crypto/sha512.(*digest).checkSum
func (d *digest) checkSum() [sha512.Size]byte

//go:linkname (*digest).Reset crypto/sha512.(*digest).Reset
func (d *digest) Reset()

//go:linkname (*digest).Write crypto/sha512.(*digest).Write
func (d *digest) Write(p []byte) (n int, err error)

func Sum512_256s(ars ...[]byte) (sum256 *[sha512.Size256]byte) {
	d := digest{function: crypto.SHA512_256}
	d.Reset()
	for _, data := range ars {
		d.Write(data)
	}
	sum := d.checkSum()
	sum256 = new([sha512.Size256]byte)
	copy(sum256[:], sum[:sha512.Size256])
	return
}

func computeCacheKey(s *Session) *[sha512.Size256]byte {
	var tmp [5]byte
	binary.BigEndian.PutUint16(tmp[0:2], s.Qtype)
	binary.BigEndian.PutUint16(tmp[2:4], s.Qclass)
	if s.OPTOrigin != nil && s.OPTOrigin.Do() {
		tmp[4] = 1
	}
	return Sum512_256s(tmp[:], []byte(s.Name))
	//h.Sum(sum[:0]) //I don't like keeping writing and summing
}
*/

var seed = maphash.MakeSeed()

func computeCacheKey(s *Session) uint64 {
	var tmp [5]byte
	binary.BigEndian.PutUint16(tmp[0:2], s.Qtype)
	binary.BigEndian.PutUint16(tmp[2:4], s.Qclass)
	if s.OPTOrigin != nil && s.OPTOrigin.Do() {
		tmp[4] = 1
	}
	var h maphash.Hash
	h.SetSeed(seed)
	h.Write(tmp[:])
	h.Write([]byte(s.Name))
	return h.Sum64()
}

func (cp *CP) setIPResponse(s *Session, ip *common.Endpoint) {
	s.Response = &dns.Msg{}
	s.Response.SetReply(s.Request)
	rr := dns.TypeToRR[s.Qtype]()
	*rr.Header() = dns.RR_Header{Name: s.Name, Rrtype: s.Qtype, Class: dns.ClassINET, Ttl: *cp.CloakTTL*60}
	switch s.Qtype {
	case dns.TypeA:     rr.(*dns.A).A = ip.IP
	case dns.TypeAAAA : rr.(*dns.AAAA).AAAA = ip.IP
	}
	s.Response.Answer = []dns.RR{rr}
}

func (cp *CP) setNegativeResponse(s *Session, rf, nx bool) {
	s.Response = &dns.Msg{}
	if nx {
		s.Response.SetRcode(s.Request, dns.RcodeNameError)
	}
	//`refused`(default)
	if rf {
		s.Response.SetRcode(s.Request, dns.RcodeRefused)
	}
	if cp.BlackTTL != nil {
		s.Response.Answer = append(s.Response.Answer, &dns.CNAME{Hdr:dns.RR_Header{
		Dot,
		dns.TypeCNAME,
		dns.ClassINET,
		*cp.BlackTTL*60, 0}, Target:s.Name})
	}
}

func (cp *CP) match(s *Session, target *string, cp2 bool) *bool {
	if cp.actions != nil {
		matches := cp.actions.FindStringSubmatchIndex(*target)
		if matches != nil {
			for idx, any := range cp.actions.Anycast {
				if matches[idx*2] != -1 {
					if ip, ok := any.(*common.Endpoint); ok {
						cp.setIPResponse(s, ip)
						return &cp.true
					}
					domain := any.(*string)
					if cp2 {
						return cp.match(s, domain, cp2)
					}
					s.Request.Question[0] = s.Request.Question[0] // QAQ QWQ QVQ - pretty go style
					s.Request.Question[0].Name = *domain
					return nil
				}
			}
			if cp.actions.Refused > 0 && matches[cp.actions.Refused*2] != -1 {
				cp.setNegativeResponse(s, true, false)
				return &cp.true
			}
			if cp.actions.NXDOMAIN > 0 && matches[cp.actions.NXDOMAIN*2] != -1 {
				cp.setNegativeResponse(s, false, true)
				return &cp.true
			}
		}
	}
	return &cp.false
}

func preloading(r Channel, domains []*string, ipv6 bool, idx uint8) {
	tmp := &Session{Listener:idx, ServerName:&svrName}
	tmp.LastState = A1_OK
	for _, str := range domains {
		domain := *str
		var s Session = *tmp
		s.Request = &dns.Msg{}
		t := dns.TypeA
		if ipv6 {
			t = dns.TypeAAAA
		}
		s.Request.SetQuestion(domain, t)
		s.Request.Id = 0
		s.Question = &s.Request.Question[0]
		Handle(r, &s)
	}
}

func (cp *CP) Handle(s *Session) Channel {
	if s.LastState == A1_OK {
		goto CP1
	}
	if s.LastState == V3_OK {
		goto CP2
	}
	panic(Session_State_Error)
StateN:
	s.State |= s.LastState
	return cp.f(StateNChannel[s.LastState])
CP1_NOK:
	s.ServerName = &svrName
	s.LastState = CP1_NOK
	goto StateN
CP1:{
	if cp.cache != nil || cp.clock_cache != nil {
		s.hash_key = computeCacheKey(s)
	}
	if cp.clock_cache != nil {
		cachedAny, ok := cp.clock_cache.Get(s.hash_key)
		if ok {
			ce := cachedAny.(clockEntry)
			if s.Listener != 0 && ce.pll != nil && cp.cache != nil {
				if s.pl_job == nil {
					s.pl_job = &sync.Once{}
				}
				s.pl_job.Do(func() {
					domains := cp.preloadings[*ce.pll:*ce.plh]
					ipv6 := s.Qtype == dns.TypeAAAA
					common.Program_dbg_full_log("start preloading...")
					go preloading(cp, domains, ipv6, s.Listener)
				})
			}
			if ce.rf || ce.nx {
				cp.setNegativeResponse(s, ce.rf, ce.nx)
			} else if ce.nc {
				goto CP1_match
			} else if ce.Value != nil {
				ep := ce.Load().(*common.EPRing)
				ce.Store(ep.Next())
				cp.setIPResponse(s,ep.Endpoint)
			} else {
				goto CP1_cache
			}
			goto CP1_NOK
		}
	}
CP1_cache:
	if cp.cache != nil {
		cachedAny, ok := cp.cache.Get(s.hash_key)
		if ok {
			s.Response = cachedAny.(inCacheResponse).Msg
			if time.Now().After(cachedAny.(inCacheResponse).expiration) {
				s.LastState = CP1_OK
				goto StateN
			}
			goto CP1_NOK
		}
	}
CP1_match:
	if matched := cp.match(s, &s.Request.Question[0].Name, false); matched != nil {
		if *matched {
			goto CP1_NOK
		}
	} else {
		goto CP1
	}
	s.LastState = CP1_OK
	goto StateN
	}
CP2:{
	if cp.startup != nil {
		// post-remote
		cp.startup.Do(func() {
			domains := cp.preloadings[*cp.pll:*cp.plh]
			go preloading(cp, domains, false, s.Listener)
			if cp.BlockIPv6 != nil && !*cp.BlockIPv6 {
				go preloading(cp, domains, true, s.Listener)
			}
		})
	}
	for _, rr := range s.Response.Answer {
		header := rr.Header()
		if header.Class != dns.ClassINET || header.Rrtype != dns.TypeCNAME {
			continue
		}
		if matched := cp.match(s, &rr.(*dns.CNAME).Target, true); *matched {
			s.LastError = (&Error_CP_Reason{Ex:rr.(*dns.CNAME).Target}).CPCNAMEExplication()
			s.LastState = CP2_NOK
			goto StateN
		}
	}
	switch s.Response.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		if s.Name != s.Request.Question[0].Name { //AS
			if len(s.Response.Question) > 0 {
				s.Response.Question[0].Name = s.Name
			}
			s.Response.Answer = append(s.Response.Answer, &dns.CNAME{Hdr:dns.RR_Header{
				s.Name,
				dns.TypeCNAME,
				dns.ClassINET,
				0, 0,}, Target:s.Request.Question[0].Name})
		}
		if cp.cache != nil {
			cp.cache.Add(s.hash_key, inCacheResponse{expiration:time.Now().Add(time.Minute * time.Duration(*cp.CacheTTL)), Msg:s.Response,})
		}
	}
	s.LastState = CP2_OK
	goto StateN
	}
}
