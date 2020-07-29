package main

import (
	"crypto/sha512"
	"encoding/binary"
	"math"
	"time"

	"github.com/miekg/dns"
	"github.com/jedisct1/dlog"
)

type CachedResponse struct {
	*dns.Msg
	expiration time.Time
}

type CachedResponses struct {
	cache *Cache
}

var cachedResponses CachedResponses

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
}

func (plugin *PluginCache) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginCache) Drop() error {
	return nil
}

func (plugin *PluginCache) Reload() error {
	return nil
}

func (plugin *PluginCache) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	cachedAny, ok := cachedResponses.cache.Get(*pluginsState.hash_key)
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
}

func (plugin *PluginCacheResponse) Name() string {
	return "cache_response"
}

func (plugin *PluginCacheResponse) Description() string {
	return "DNS cache (writer)."
}

func (plugin *PluginCacheResponse) Init(proxy *Proxy) error {
	if cachedResponses.cache == nil {
		size := 1<<math.Ilogb(float64(proxy.cacheSize))
		dlog.Debugf("accurate cache size: %d", size)
		cachedResponses.cache = NewCache(size)
	}
	return nil
}

func (plugin *PluginCacheResponse) Drop() error {
	return nil
}

func (plugin *PluginCacheResponse) Reload() error {
	return nil
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

	cachedResponses.cache.Add(*pluginsState.hash_key, cachedResponse)
	updateTTL(msg, cachedResponse.expiration)

	return nil
}
