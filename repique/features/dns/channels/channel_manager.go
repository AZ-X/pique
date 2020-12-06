package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
)

const (
	Channel_Starter      = "Star" // *
	Channel_End          = "E"
	Channel_Validation   = "V"
	Channel_Amender      = "A"
	Channel_CP           = "CP" // caches and patterns; unitized handling
	Channel_Remote       = "Resolver" // server selection & query over recursive resolvers
	Channel_Logger       = "Log"

	Dot                  = "."
	EMPTY                = "-"
	NonSvrName           = EMPTY
	Session_State_Error  = "session contains wrong state"
	DefaultTTL    uint32 = 60
)

// 'Error' represents a fixed conclusion error thrown by channels.
type Error struct{ Ex string }

func (e *Error) Error() string {
	return e.Ex
}

type FChannelByName func(string) Channel

type Channel interface {
	Name() string
	Init(*Config, FChannelByName)
	Handle(*Session) Channel // chain of reaction
}

// A simple channel manager across all listeners
type ChannelMgr struct {
	*ListenerCfg
	channels_list map[int]map[string]Channel
}

func (mgr *ChannelMgr) Init(listeners int) {
	s := &Starter{}
	e := &End{}
	mgr.ListenerCfg = &ListenerCfg{Cfgs:make(map[int]*Config, listeners)}
	mgr.channels_list = make(map[int]map[string]Channel, listeners)
	for idx := 1; idx <= listeners; idx++ {
		mgr.channels_list[idx] = make(map[string]Channel)
		mgr.Register(idx, s)
		mgr.Register(idx, e)
	}
}

//individual,shares : array of listener idx
func (mgr *ChannelMgr) InitChannels(individual []int, shares []int) {
	for _, idx := range individual {
		mgr.Register(idx, &Amender{})
		mgr.Register(idx, &Logger{})
		mgr.Register(idx, &CP{})
		mgr.Register(idx, &Validation{})
	}
	if len(shares) != 0 {
		mgr.Registers(shares, &Amender{})
		mgr.Registers(shares, &Logger{})
		mgr.Registers(shares, &CP{})
		mgr.Registers(shares, &Validation{})
	}
}

func (mgr *ChannelMgr) Register(idx int, ch Channel) {
	var f FChannelByName = func(name string) Channel {
		return mgr.channels_list[idx][name]
	}
	ch.Init(mgr.Cfgs[idx], f)
	mgr.channels_list[idx][ch.Name()] = ch
}

func (mgr *ChannelMgr) Registers(shares []int, ch Channel) {
	for _, idx := range shares {
		var f FChannelByName = func(name string) Channel {
			return mgr.channels_list[idx][name]
		}
		ch.Init(mgr.Cfgs[idx], f)
		mgr.channels_list[idx][ch.Name()] = ch
	}
}

// can bypass default only if initial state != star
const handler_safe_throttle = 20
func (mgr *ChannelMgr) Handle(session *Session) {
	for channel, counter := mgr.channels_list[session.Listener][Channel_Starter], 0; counter < handler_safe_throttle && channel != nil; counter++ {
		channel = channel.Handle(session)
	}
}

type ListenerCfg struct {
	Cfgs map[int]*Config
}

type Config struct {
	QueryMeta                []string                     `toml:"query_meta"`
	CacheSize                *int                         `toml:"cache_size"`
	BlockIPv6                *bool                        `toml:"sinkhole_ipv6"`
	CacheTTL                 *uint32                      `toml:"cache_ttl"` // default an hour
	CloakTTL                 *uint32                      `toml:"cloak_ttl"` // default an hour
	BlackTTL                 *uint32                      `toml:"black_ttl"` //a.k.a. TTL of negative responses; no default
	NodataTTL                *uint32                      `toml:"nodata_ttl"` // default an hour; sinkhole_ipv6 pops nodata RR
	BlackCloaking            *string                      `toml:"black_cloaking_routine"`
	BlackCloakingMon         *bool                        `toml:"windows_filemon"`
	BlockedQueryResponse     string                       `toml:"blocked_query_response"`
	QueryLog                 *QueryLogConfig              `toml:"query_log"`
}

type QueryLogConfig struct {
	File                     *string                      `toml:"file"`
	Format                   *string                      `toml:"format"`
	IgnoredQtypes            []string                     `toml:"ignored_qtypes"`
}

type Starter struct {
	f FChannelByName
}

func (_ *Starter) Name() string {
	return Channel_Starter
}

func (s *Starter) Init(_ *Config, f FChannelByName) {
	s.f = f
}

func (s *Starter) Handle(ss *Session) Channel {
	ss.State |= ss.LastState
	return s.f(StateNChannel[ss.LastState])
}

type End struct {
}

func (_ *End) Name() string {
	return Channel_End
}

func (_ *End) Init(_ *Config, _ FChannelByName) {
}

func (_ *End) Handle(s *Session) Channel {
	s.LastState = E
	s.State |= s.LastState
	return nil
}

