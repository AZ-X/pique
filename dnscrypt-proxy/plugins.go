package main

import (
	"errors"
	"net"
	"time"
	"encoding/json"
	
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type pluginsState int

const (
	PluginsStateNone     = 0
	PluginsStateDrop     = 1
	PluginsStateReject   = 2
	PluginsStateSynth    = 3
)

type PluginsGlobals struct {
	*PluginsShareObjects
	queryPlugins           *[]Plugin
	responsePlugins        *[]Plugin
	loggingPlugins         *[]Plugin
}

type PluginsShareObjects struct {
	blockmatcher    *regexp_builder
	block_logger    *lumberjack.Logger
	block_format    *string
	cache           *Cache
}

type PluginsReturnCode int

const (
	PluginsReturnCodePass = iota
	PluginsReturnCodeForward
	PluginsReturnCodeDrop
	PluginsReturnCodeReject
	PluginsReturnCodeSynth
	PluginsReturnCodeParseError
	PluginsReturnCodeNXDomain
	PluginsReturnCodeResponseError
	PluginsReturnCodeServFail
	PluginsReturnCodeNetworkError
	PluginsReturnCodeCloak
	PluginsReturnCodeServerTimeout
)

var PluginsReturnCodeToString = map[PluginsReturnCode]string{
	PluginsReturnCodePass:          "PASS",
	PluginsReturnCodeForward:       "FORWARD",
	PluginsReturnCodeDrop:          "DROP",
	PluginsReturnCodeReject:        "REJECT",
	PluginsReturnCodeSynth:         "SYNTH",
	PluginsReturnCodeParseError:    "PARSE_ERROR",
	PluginsReturnCodeNXDomain:      "NXDOMAIN",
	PluginsReturnCodeResponseError: "RESPONSE_ERROR",
	PluginsReturnCodeServFail:      "SERVFAIL",
	PluginsReturnCodeNetworkError:  "NETWORK_ERROR",
	PluginsReturnCodeCloak:         "CLOAK",
	PluginsReturnCodeServerTimeout: "SERVER_TIMEOUT",
}

// should rename to SessionState
// seems no reason to keep too much fields other than weak typed sessionData
// should clean toilet before use, next time ...
type PluginsState struct {
	sessionData                      map[string]interface{}
	state                            pluginsState
	maxUnencryptedUDPSafePayloadSize int
	originalMaxPayloadSize           int
	maxPayloadSize                   int
	idx                              int
	cacheNegMinTTL                   uint32
	cacheNegMaxTTL                   uint32
	cacheMinTTL                      uint32
	cacheMaxTTL                      uint32
	clientProto                      *string
	qName                            *string
	serverName                       *string
	hash_key                         *[32]byte
	requestStart                     time.Time
	requestEnd                       time.Time
	clientAddr                       *net.Addr
	synthResponse                    *dns.Msg
	dnssec                           bool
	cacheHit                         bool
	returnCode                       PluginsReturnCode
}

func (p PluginsState) ServerName() string {
	if p.serverName == nil {
		return NonSvrName
	} else {
		return *(p.serverName)
	}
}


func (proxy *Proxy) InitPluginsGlobals() error {
	if len(proxy.userName) > 0 && !proxy.child {
		return nil
	}
	queryPlugins := &[]Plugin{}
	if len(proxy.blockNameFile) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockName)))
	}
	if proxy.pluginBlockIPv6 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockIPv6)))
	}
	if proxy.pluginBlockUnqualified {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockUnqualified)))
	}
	if len(proxy.cloakFile) != 0 {
		proxy.calc_hash_key = true
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginCloak)))
	}
	if proxy.cache {
		proxy.calc_hash_key = true
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginCache)))
	}
	if len(proxy.queryMeta) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginQueryMeta)))
	}
	*queryPlugins = append(*queryPlugins, Plugin(new(PluginGetSetPayloadSize)))
	responsePlugins := &[]Plugin{}
	if len(proxy.nxLogFile) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginNxLog)))
	}
	if len(proxy.blockNameFile) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginBlockNameResponse)))
	}
	if proxy.cache {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginCacheResponse)))
	}
	loggingPlugins := &[]Plugin{}
	if len(proxy.queryLogFile) != 0 {
		*loggingPlugins = append(*loggingPlugins, Plugin(new(PluginQueryLog)))
	}
	proxy.pluginsGlobals = &PluginsGlobals{PluginsShareObjects : &PluginsShareObjects{},}
	for _, plugin := range *queryPlugins {
		if err := plugin.Init(proxy); err != nil {
			return err
		}
	}
	for _, plugin := range *responsePlugins {
		if err := plugin.Init(proxy); err != nil {
			return err
		}
	}
	for _, plugin := range *loggingPlugins {
		if err := plugin.Init(proxy); err != nil {
			return err
		}
	}
	proxy.pluginsGlobals.queryPlugins = queryPlugins
	proxy.pluginsGlobals.responsePlugins = responsePlugins
	proxy.pluginsGlobals.loggingPlugins = loggingPlugins

	return nil
}

type Plugin interface {
	Init(proxy *Proxy) error
	Eval(pluginsState *PluginsState, msg *dns.Msg) error
}

func NewPluginsState(proxy *Proxy, clientProto string, clientAddr *net.Addr, start time.Time, idx int)*PluginsState {
	return &PluginsState{
		state:                            PluginsStateNone,
		returnCode:                       PluginsReturnCodePass,
		maxPayloadSize:                   MaxDNSUDPPacketSize - ResponseOverhead,
		clientProto:                      &clientProto,
		clientAddr:                       clientAddr,
		cacheNegMinTTL:                   proxy.cacheNegMinTTL,
		cacheNegMaxTTL:                   proxy.cacheNegMaxTTL,
		cacheMinTTL:                      proxy.cacheMinTTL,
		cacheMaxTTL:                      proxy.cacheMaxTTL,
		qName:                            nil,
		requestStart:                     start,
		maxUnencryptedUDPSafePayloadSize: MaxDNSUDPSafePacketSize,
		sessionData:                      make(map[string]interface{}),
		idx:                              idx,
	}
}

func (pluginsState *PluginsState) PreEvalPlugins(proxy *Proxy, packet []byte, serverName *string) (*dns.Msg, uint16) {
	pluginsGlobals := proxy.pluginsGlobals
	pluginsState.serverName = serverName
	goto Go
ERROR:
	pluginsState.state = PluginsStateDrop
	return nil, 0
Go:
	msg := &dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		dlog.Warnf(">>>>>>>>>>>>>>>>>>>>>dns packet error: %v", err)
		goto ERROR
	}
	if len(msg.Question) != 1 {
		dlog.Warnf(">>>>>>>>>>>>>>>>>>>>>unexpected number of questions: %d", len(msg.Question))
		goto ERROR
	}
	qName, err := NormalizeQName(msg.Question[0].Name)
	if err != nil {
		dlog.Warnf(">>>>>>>>>>>>>>>>>>>>>normalize qname error: %v", err)
		goto ERROR
	}
	
	pluginsState.qName = &qName
	if edns0 := msg.IsEdns0(); edns0 != nil && edns0.Do() {
		pluginsState.dnssec = true
	}
	if proxy.calc_hash_key {
		pluginsState.hash_key = ComputeCacheKey(pluginsState, msg)
	}
	for _, plugin := range *pluginsGlobals.queryPlugins {
		if err := plugin.Eval(pluginsState, msg); err != nil {
			dlog.Warnf(">>>>>>>>>>>>>>>>>>>>>QueryPlugins return error: %v", err)
			goto ERROR
		}
		if pluginsState.state == PluginsStateReject {
			pluginsState.synthResponse = RefusedResponseFromMessage(msg, proxy.blockedQueryResponse)
		}
		if pluginsState.state != PluginsStateNone {
			break
		}
	}
	//SetDNSSECFlag(msg)
	if program_dbg_full {
		bin, err := json.Marshal(msg)
		if err == nil {
			jsonStr := string(bin)
			dlog.Debug("[processed request]:" + jsonStr)
		}
	}
	id := msg.Id
	msg.Id = 0
	return msg, id
}


func (pluginsState *PluginsState) ApplyEDNS0PaddingQueryPlugins(msg *dns.Msg) {
	padLen := 63 - ((msg.Len() + 63) & 63)
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(uint16(MaxDNSPacketSize), false)
		opt = msg.IsEdns0()
		if opt == nil {
			return
		}
	}
	for _, option := range opt.Option {
		if option.Option() == dns.EDNS0PADDING {
			return
		}
	}
	
	ext := new(dns.EDNS0_PADDING)
	padding := make([]byte, padLen)
	for i,_ := range padding {
		padding[i] = 0x00
	}
	ext.Padding = padding[:padLen]
	opt.Option = append(opt.Option, ext)
}

func (pluginsState *PluginsState) PostEvalPlugins(proxy *Proxy, request *dns.Msg, response *dns.Msg, id uint16) (*dns.Msg) {
	var bin []byte
	var err error
	var jsonStr string
	pluginsGlobals := proxy.pluginsGlobals
	if request == nil {
		return nil
	}
	if response == nil {
		if pluginsState.synthResponse != nil {
			response = pluginsState.synthResponse
		} else {
			response = &dns.Msg{}
			response.SetReply(request)
		}
		switch pluginsState.returnCode {
		case PluginsStateReject:
			response.Rcode = dns.RcodeRefused
		case PluginsReturnCodeServerTimeout, PluginsReturnCodeServFail:
			response.Rcode = dns.RcodeServerFailure
		}
		goto SetId
	}
	if program_dbg_full {
		dlog.Debugf("[RAW response length]: %d", response.Len())
		bin, err = json.Marshal(response)
		if err == nil {
			jsonStr = string(bin)
			dlog.Debug("[RAW response]:" + jsonStr)
		}
	}
	response.Compress = true
	
	switch response.Rcode {
	case dns.RcodeSuccess:
		pluginsState.returnCode = PluginsReturnCodePass
	case dns.RcodeNameError:
		pluginsState.returnCode = PluginsReturnCodeNXDomain
	case dns.RcodeServerFailure:
		pluginsState.returnCode = PluginsReturnCodeServFail
	case dns.RcodeRefused:
		pluginsState.returnCode = PluginsReturnCodeReject
	case dns.RcodeFormatError:
	pluginsState.returnCode = PluginsReturnCodeParseError	
	default:
		dlog.Warnf("===========================>error on QName %v Rcode: %v", pluginsState.qName, response.Rcode)
		pluginsState.returnCode = PluginsReturnCodeResponseError
	}

	//removeEDNS0Options(&response)  dnssec gone?

	for _, plugin := range *pluginsGlobals.responsePlugins {
		if err := plugin.Eval(pluginsState, response); err != nil {
			dlog.Warnf("===========================>error on Eval(response): %v", err)
			pluginsState.state = PluginsStateDrop
		}
		if pluginsState.state == PluginsStateReject {
			pluginsState.synthResponse = RefusedResponseFromMessage(response, proxy.blockedQueryResponse)
			response = pluginsState.synthResponse
		}
		if pluginsState.state != PluginsStateNone {
			break
		}
	}
SetId:
	response.Id = id
	if program_dbg_full {
		bin, err = json.Marshal(response)
		if err == nil {
			jsonStr = string(bin)
			dlog.Debug("[processed response]:" + jsonStr)
		}
	}
	return response
}

func (pluginsState *PluginsState) ApplyLoggingPlugins(pluginsGlobals *PluginsGlobals, request *dns.Msg) error {
	if len(*pluginsGlobals.loggingPlugins) == 0 {
		return nil
	}
	pluginsState.requestEnd = time.Now()
	if request == nil {
		return errors.New("Question not found")
	}
	for _, plugin := range *pluginsGlobals.loggingPlugins {
		if err := plugin.Eval(pluginsState, request); err != nil {
			return err
		}
	}
	return nil
}
