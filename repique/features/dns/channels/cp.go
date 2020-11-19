package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
	"crypto/sha512"
	"encoding/binary"
	"io/ioutil"
	"math"
	"regexp"
	"strings"
	"time"
	

	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/services"
	"github.com/AZ-X/pique/repique/conceptions"
	
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

const (
	RF                  = "RF"
	NX                  = "NX"
)

type clockEntry struct {
	*common.EPRing
}

type inCacheResponse struct {
	*dns.Msg
	expiration time.Time
}


// caches and patterns; unitized handling
type CP struct {
	*Config
	f              FChannelByName
	actions        *services.Regex_Actions
	clock_cache    *conceptions.CloakCache
	cache          *conceptions.Cache
}

func (cp *CP) Name() string {
	return Channel_CP
}

func (cp *CP) Init(cfg *Config, f FChannelByName) {
	cp.Config = cfg
	cp.f = f
	ttl := DefaultTTL
	if cfg.BlackCloaking != nil {
		bin, err := ioutil.ReadFile(*cfg.BlackCloaking)
		if err != nil {
			panic(err)
		}
		cloaks := make(map[string]map[string][]*common.Endpoint)
		var nxs, rfs []string
		ips := make([]struct{*common.Endpoint; Exps []string}, 0)
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
			var rf, nx bool
			var ip *common.Endpoint
			switch match[exp.SubexpIndex("target")] {
			case RF: rf = true
			case NX: nx = true
			default: if ip, err = common.ResolveEndpoint(match[exp.SubexpIndex("target")]); err != nil {
					dlog.Errorf("at line %d, err:%v", line+1, err)
					panic("unrecognized ip address found in black_cloaking_routine, check it before use")
					}
			}
			patterns := whitespaces.Split(match[exp.SubexpIndex("patterns")], -1)
			var exps []string
			for _, str := range patterns {
				pattern := strings.TrimPrefix(str, `/`)
				if len(pattern) == len(str) {
					cloaking, found := cloaks[pattern]
					if !found {
						cloaking = make(map[string][]*common.Endpoint)
					}
					if ip.IP.To4() != nil {
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
					} else {
						exps = append(exps, pattern)
					}
				}
			}
			if len(exps) != 0 {
				ips = append(ips, struct{*common.Endpoint; Exps []string}{ip,exps})
			}
		}
		if len(rfs) != 0 || len(nxs) != 0 || len(ips) != 0 {
			cp.actions = services.CreateRegexActions(rfs, nxs, ips)
		}
		preComputeCacheKey := func(qtype uint16, name string) [32]byte {
			h := sha512.New512_256()
			var tmp [5]byte
			binary.BigEndian.PutUint16(tmp[0:2], qtype)
			binary.BigEndian.PutUint16(tmp[2:4], dns.ClassINET)
			h.Write(tmp[:])
			h.Write([]byte(name))
			var sum [32]byte
			h.Sum(sum[:0])
			return sum
		}
		if len(cloaks) != 0 {
			cp.clock_cache = conceptions.NewCloakCache()
			for name,r := range cloaks {
				if len(r["v4"]) > 0 {
					key := preComputeCacheKey(dns.TypeA, name)
					value := clockEntry{EPRing:common.LinkEPRing(r["v4"]...),} 
					cp.clock_cache.Add(key, value)
				}
				if len(r["v6"]) > 0 {
					key := preComputeCacheKey(dns.TypeAAAA, name)
					value := clockEntry{EPRing:common.LinkEPRing(r["v6"]...),} 
					cp.clock_cache.Add(key, value)
				}
			}
			if cfg.CloakTTL == nil {
				cfg.CloakTTL = &ttl
			}
		}
	}
	if cfg.CacheSize != nil {
		size := 1<<math.Ilogb(float64(*cfg.CacheSize))
		dlog.Debugf("accurate cache size: %d", size)
		cp.cache = conceptions.NewCache(size)
		if cfg.CacheTTL == nil {
			cfg.CacheTTL = &ttl
		}
	}
}

func computeCacheKey(s *Session) *[32]byte {
	h := sha512.New512_256()
	var tmp [5]byte
	binary.BigEndian.PutUint16(tmp[0:2], s.Qtype)
	binary.BigEndian.PutUint16(tmp[2:4], s.Qclass)
	if s.OPTOrigin != nil && s.OPTOrigin.Do() {
		tmp[4] = 1
	}
	h.Write(tmp[:])
	normalizedRawQName := []byte(s.Name)
	h.Write(normalizedRawQName)
	var sum [32]byte
	h.Sum(sum[:0])
	return &sum
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

func (cp *CP) match(s *Session, target *string) bool {
	if cp.actions != nil {
		matches := cp.actions.FindStringSubmatchIndex(*target)
		if matches != nil {
			for idx, ip := range cp.actions.IPAddress {
				if matches[idx*2] != -1 {
					cp.setIPResponse(s, ip)
					return true
				}
			}
			if cp.actions.Refused > 0 && matches[cp.actions.Refused*2] != -1 {
				s.Response = &dns.Msg{}
				s.Response.SetRcode(s.Request, dns.RcodeRefused)
				goto SetNGTTL
			}
			if cp.actions.NXDOMAIN > 0 && matches[cp.actions.NXDOMAIN*2] != -1 {
				s.Response = &dns.Msg{}
				s.Response.SetRcode(s.Request, dns.RcodeNameError)
				goto SetNGTTL
			}
		}
	}
	return false
SetNGTTL:
	if cp.BlackTTL != nil {
		s.Response.Answer = append(s.Response.Answer, &dns.CNAME{Hdr:dns.RR_Header{
		Dot,
		dns.TypeCNAME,
		dns.ClassINET,
		*cp.BlackTTL*60, 0}, Target:s.Name})
	}
	return true
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
	s.LastState = CP1_NOK
	goto StateN
CP1:{
	if cp.cache != nil || cp.clock_cache != nil {
		s.hash_key = computeCacheKey(s)
	}
	if cp.clock_cache != nil {
		cachedAny, ok := cp.clock_cache.Get(*s.hash_key)
		if ok {
			ce := cachedAny.(clockEntry)
			ce.EPRing = ce.Next()
			cp.setIPResponse(s, ce.Endpoint)
			goto CP1_NOK
		}
	}
	if cp.cache != nil {
		cachedAny, ok := cp.cache.Get(*s.hash_key)
		if ok {
			s.Response = cachedAny.(inCacheResponse).Msg
			if time.Now().After(cachedAny.(inCacheResponse).expiration) {
				s.LastState = CP1_OK
				goto StateN
			}
			goto CP1_NOK
		}
	}
	if cp.match(s, &s.Name) {
		goto CP1_NOK
	}
	s.LastState = CP1_OK
	goto StateN
	}
CP2:{
	for _, rr := range s.Response.Answer {
		header := rr.Header()
		if header.Class != dns.ClassINET || header.Rrtype != dns.TypeCNAME {
			continue
		}
		if cp.match(s, &rr.(*dns.CNAME).Target) {
			s.LastState = CP2_NOK
			goto StateN
		}
	}
	if cp.cache != nil {
		cp.cache.Add(*s.hash_key, inCacheResponse{expiration:time.Now().Add(time.Minute * time.Duration(*cp.CacheTTL)), Msg:s.Response,})
	}
	s.LastState = CP2_OK
	goto StateN
	}
}
