package channels

import (
	"crypto/sha512"
	"encoding/binary"
	"math"
	"time"

	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/conceptions"
	"github.com/miekg/dns"
	"github.com/jedisct1/dlog"
)

type CachedResponse struct {
	*dns.Msg
	expiration time.Time
}

func ComputeCacheKey(pluginsState *PluginsState, msg *dns.Msg) *[32]byte {
	question := msg.Question[0]
	return computeCacheKey(pluginsState.dnssec, question.Qtype, question.Qclass, question.Name)
}

func computeCacheKey(dnssec bool, Qtype, Qclass uint16, Name string) *[32]byte {
	h := sha512.New512_256()
	var tmp [5]byte
	binary.BigEndian.PutUint16(tmp[0:2], Qtype)
	binary.BigEndian.PutUint16(tmp[2:4], Qclass)
	if dnssec {
		tmp[4] = 1
	}
	h.Write(tmp[:])
	normalizedRawQName := []byte(dns.CanonicalName(Name))
	h.Write(normalizedRawQName)
	var sum [32]byte
	h.Sum(sum[:0])

	return &sum
}

// ---

type PluginCache struct {
	cache *conceptions.Cache
}

func (plugin *PluginCache) Init(proxy *Proxy) error {
	size := 1<<math.Ilogb(float64(proxy.CacheSize))
	dlog.Debugf("accurate cache size: %d", size)
	proxy.pluginsGlobals.cache = conceptions.NewCache(size)
	plugin.cache = proxy.pluginsGlobals.cache
	return nil
}


func updateTTL(msg *dns.Msg, expiration time.Time) {
	until := time.Until(expiration)
	ttl := uint32(0)
	if until > 0 {
		ttl = uint32(until / time.Second)
	}
	for _, rr := range msg.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
}


func (plugin *PluginCache) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	cachedAny, ok := plugin.cache.Get(*pluginsState.hash_key)
	if !ok {
		return nil
	}
	synth := cachedAny.(CachedResponse)
	synth.Id = msg.Id
	synth.Response = true
	synth.Compress = true

	if time.Now().After(synth.expiration) {
		dlog.Debugf("cache expired from %v", synth.expiration)
		pluginsState.sessionData["stale"] = synth.Msg
		return nil
	}

	updateTTL(synth.Msg, synth.expiration)

	pluginsState.synthResponse = synth.Msg
	pluginsState.state = PluginsStateSynth
	pluginsState.cacheHit = true
	return nil
}

// ---

type PluginCacheResponse struct {
	cache *conceptions.Cache
}

func (plugin *PluginCacheResponse) Init(proxy *Proxy) error {
	plugin.cache = proxy.pluginsGlobals.cache
	return nil
}

func getMinTTL(msg *dns.Msg, minTTL uint32, maxTTL uint32, cacheNegMinTTL uint32, cacheNegMaxTTL uint32) time.Duration {
	if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) || (len(msg.Answer) <= 0 && len(msg.Ns) <= 0) {
		return time.Duration(cacheNegMinTTL) * time.Second
	}
	var ttl uint32
	if msg.Rcode == dns.RcodeSuccess {
		ttl = uint32(maxTTL)
	} else {
		ttl = uint32(cacheNegMaxTTL)
	}
	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		for _, rr := range msg.Ns {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	if msg.Rcode == dns.RcodeSuccess {
		if ttl < minTTL {
			ttl = minTTL
		}
	} else {
		if ttl < cacheNegMinTTL {
			ttl = cacheNegMinTTL
		}
	}
	return time.Duration(ttl) * time.Minute
}


func (plugin *PluginCacheResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError && msg.Rcode != dns.RcodeNotAuth {
		return nil
	}
	if msg.Truncated {
		return nil
	}
	ttl := getMinTTL(msg, pluginsState.cacheMinTTL, pluginsState.cacheMaxTTL, pluginsState.cacheNegMinTTL, pluginsState.cacheNegMaxTTL)
	cachedResponse := CachedResponse{
		expiration: time.Now().Add(ttl),
		Msg:        msg,
	}

	plugin.cache.Add(*pluginsState.hash_key, cachedResponse)
	updateTTL(msg, cachedResponse.expiration)

	return nil
}
