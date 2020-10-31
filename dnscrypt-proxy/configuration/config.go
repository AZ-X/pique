package configuration

import (
	"errors"
	"flag"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"context"
	"runtime"
	
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/behaviors"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/features/dns"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/conceptions"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/protocols/tls"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/services"
	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
	stamps "stammel"
	"golang.org/x/sync/semaphore"
)

const (
	DefaultNetprobeAddress = "127.0.0.1:53"
)

type Config struct {
	Cache                    bool
	Timeout                  int                         `toml:"Timeout"`
	KeepAlive                int                         `toml:"keepalive"`
	CertRefreshDelay         int                         `toml:"cert_refresh_delay"`
	CacheSize                int                         `toml:"Cache_size"`
	NetprobeTimeout          int                         `toml:"netprobe_Timeout"`
	LogMaxSize               int                         `toml:"log_files_max_size"`
	LogMaxAge                int                         `toml:"log_files_max_age"`
	LogMaxBackups            int                         `toml:"log_files_max_backups"`
	LogLevel                 int                         `toml:"log_level"`
	LogFile                  *string                     `toml:"log_file"`
	ServerNames              []string                    `toml:"server_names"`
	DisabledServerNames      []string                    `toml:"disabled_server_names"`
	ListenAddresses          []string                    `toml:"listen_addresses"`
	QueryMeta                []string                    `toml:"query_meta"`
	OfflineMode              bool                        `toml:"offline_mode"`
	UseSyslog                bool                        `toml:"use_syslog"`
	ForceTCP                 bool                        `toml:"force_tcp"`
	BlockIPv6                bool                        `toml:"block_ipv6"`
	BlockUnqualified         bool                        `toml:"block_unqualified"`
	SourceRequireDNSSEC      bool                        `toml:"require_dnssec"`
	SourceRequireNoLog       bool                        `toml:"require_nolog"`
	SourceRequireNoFilter    bool                        `toml:"require_nofilter"`
	SourceDNSCrypt           bool                        `toml:"dnscrypt_servers"`
	SourceDoH                bool                        `toml:"doh_servers"`
	SourceDoT                bool                        `toml:"dot_servers"`
	SourceIPv4               bool                        `toml:"ipv4_servers"`
	SourceIPv6               bool                        `toml:"ipv6_servers"`
	TLSDisableSessionTickets bool                        `toml:"tls_disable_session_tickets"`
	CacheNegTTL              uint32                      `toml:"cache_neg_ttl"`
	CacheNegMinTTL           uint32                      `toml:"cache_neg_min_ttl"`
	CacheNegMaxTTL           uint32                      `toml:"cache_neg_max_ttl"`
	CacheMinTTL              uint32                      `toml:"cache_min_ttl"`
	CacheMaxTTL              uint32                      `toml:"cache_max_ttl"`
	RejectTTL                uint32                      `toml:"reject_ttl"`
	CloakTTL                 uint32                      `toml:"cloak_ttl"`
	MaxClients               uint32                      `toml:"max_clients"`
	LocalInterface           string                      `toml:"network_interface"`
	UserName                 string                      `toml:"user_name"`
	LBStrategy               string                      `toml:"lb_strategy"`
	CloakFile                string                      `toml:"cloaking_rules"`
	NetprobeAddress          string                      `toml:"netprobe_address"`
	ProxyURI                 string                      `toml:"proxy_uri"`
	ProxyIP                  string                      `toml:"proxy_ip"`
	BlockedQueryResponse     string                      `toml:"blocked_query_response"`
	StaticsConfig            map[string]StaticConfig     `toml:"static"`
	SourcesConfig            map[string]SourceConfig     `toml:"sources"`
	QueryLog                 QueryLogConfig              `toml:"query_log"`
	NxLog                    NxLogConfig                 `toml:"nx_log"`
	BlockName                BlockNameConfig             `toml:"blacklist"`
	AnonymizedDNS            AnonymizedDNSConfig         `toml:"anonymized_dns"`
	Groups                   []GroupsConfig              `toml:"groups"`
	GroupsListener           []ListenerAssociation       `toml:"listener_association"`
}

func newConfig() Config {
	return Config{
		LogLevel:                 int(dlog.LogLevel()),
		ListenAddresses:          []string{"127.0.0.1:53"},
		Timeout:                  5000,
		KeepAlive:                5,
		CertRefreshDelay:         240,
		Cache:                    true,
		CacheSize:                512,
		CacheNegTTL:              0,
		CacheNegMinTTL:           60,
		CacheNegMaxTTL:           600,
		CacheMinTTL:              60,
		CacheMaxTTL:              86400,
		RejectTTL:                600,
		CloakTTL:                 600,
		SourceRequireNoLog:       true,
		SourceRequireNoFilter:    true,
		SourceIPv4:               true,
		SourceIPv6:               false,
		SourceDoH:                true,
		SourceDoT:                true,
		SourceDNSCrypt:           true,
		MaxClients:               250,
		LogMaxSize:               10,
		LogMaxAge:                7,
		LogMaxBackups:            1,
		TLSDisableSessionTickets: false,
		NetprobeTimeout:          60,
		OfflineMode:              false,
		BlockedQueryResponse:     "refused",
	}
}

type StaticConfig struct {
	Stamp string
}

type SourceConfig struct {
	URL            string
	URLs           []string
	MinisignKeyStr string `toml:"minisign_key"`
	CacheFile      string `toml:"cache_file"`
	FormatStr      string `toml:"format"`
	RefreshDelay   int    `toml:"refresh_delay"`
	Prefix         string
}

type QueryLogConfig struct {
	File          string
	Format        string
	IgnoredQtypes []string `toml:"ignored_qtypes"`
}

type NxLogConfig struct {
	File   string
	Format string
}

type BlockNameConfig struct {
	File    string `toml:"blacklist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type AnonymizedDNSRouteConfig struct {
	ServerName string   `toml:"server_name"`
	RelayNames []string `toml:"via"`
}

type AnonymizedDNSConfig struct {
	Routes []AnonymizedDNSRouteConfig `toml:"routes"`
}

type ConfigFlags struct {
	Check                   *bool
	ConfigFile              *string
	Child                   *bool
	NetprobeTimeoutOverride *int
}

type GroupsConfig struct {
	Name           string   `toml:"name"`
	Servers        []string `toml:"servers"`
	Tag            string   `toml:"tag"`
	Groups         []string `toml:"groups"`
	Priority       bool     `toml:"priority"`
	Match          string   `toml:"match"`
}

type ListenerAssociation struct {
	Position       int     `toml:"position"`
	Group          string   `toml:"group"`
	Regex          bool     `toml:"regex"`
}


func findConfigFile(configFile *string) (string, error) {
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		cdLocal()
		if _, err := os.Stat(*configFile); err != nil {
			return "", err
		}
	}
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(*configFile) {
		return *configFile, nil
	}
	return path.Join(pwd, *configFile), nil
}

func ConfigLoad(proxy *dns.Proxy, flags *ConfigFlags) error {
	foundConfigFile, err := findConfigFile(flags.ConfigFile)
	if err != nil {
		dlog.Fatalf("failed to load the configuration file [%s]", *flags.ConfigFile)
	}
	config := newConfig()
	proxy.ProxyStartup = &dns.ProxyStartup{}
	md, err := toml.DecodeFile(foundConfigFile, &config)
	if err != nil {
		return err
	}
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return dlog.Errorf("Unsupported key in configuration file: [%s]", undecoded[0])
	}
	if err := cdFileDir(foundConfigFile); err != nil {
		return err
	}
	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	if config.UseSyslog {
		dlog.UseSyslog(true)
	} else if config.LogFile != nil {
		dlog.UseLogFile(*config.LogFile)
		if !*flags.Child {
			dns.FileDescriptors = append(dns.FileDescriptors, dlog.GetFileDescriptor())
		} else {
			dns.FileDescriptorNum++
			dlog.SetFileDescriptor(os.NewFile(uintptr(3), "logFile"))
		}
	}
	dlog.Noticef("dnscrypt-proxy %s built with %s", common.AppVersion, runtime.Version())
	dlog.Noticef("LogLevel %s", dlog.SeverityName[dlog.LogLevel()])
	proxy.UserName = config.UserName
	proxy.Child = *flags.Child
	
	proxy.ListenAddresses = config.ListenAddresses
	
	if !*flags.Child && len(proxy.UserName) > 0 && !*flags.Check {
		return nil
	}

	if len(config.LocalInterface) > 0 {
		proxy.LocalInterface = &config.LocalInterface
	}
	if config.LogLevel == int(dlog.SeverityDebug) {
		PrintInferfaceInfo(proxy.LocalInterface)
	}

	proxy.LogMaxSize = config.LogMaxSize
	proxy.LogMaxAge = config.LogMaxAge
	proxy.LogMaxBackups = config.LogMaxBackups


	proxy.XTransport = tls.NewXTransport()
	proxy.XTransport.TlsDisableSessionTickets = config.TLSDisableSessionTickets
	proxy.XTransport.KeepAlive = time.Duration(config.KeepAlive) * time.Second
	proxy.XTransport.Transports = make(map[string]*tls.TransportHolding)
	proxy.XTransport.LocalInterface = proxy.LocalInterface
	if len(config.ProxyURI) > 0 {
		globalProxy, err := url.Parse(config.ProxyURI)
		if err != nil {
			dlog.Fatalf("failed to parse the proxy URL [%v]", config.ProxyURI)
		}
		proxy.XTransport.Proxies = conceptions.InitProxies()
		var ep *common.Endpoint
		if len(config.ProxyIP) > 0 {
			
			if ep, err = common.ResolveEndpoint(config.ProxyIP); err !=nil {
				dlog.Fatalf("failed to parse the proxy IP [%v]", config.ProxyIP)
			}
		}
		proxy.XTransport.Proxies.AddGlobalProxy(globalProxy, ep)
	}

	proxy.BlockedQueryResponse = config.BlockedQueryResponse
	proxy.Timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.SmaxClients = semaphore.NewWeighted(int64(config.MaxClients))
	proxy.Ctx, proxy.Cancel = context.WithCancel(context.Background())
	proxy.MainProto = "udp"
	if config.ForceTCP {
		proxy.MainProto = "tcp"
	}
	dlog.Noticef("dnscrypt-protocol bind to %s", proxy.MainProto)
	proxy.CertRefreshDelay = time.Duration(common.Max(60, config.CertRefreshDelay)) * time.Minute
	if len(config.ListenAddresses) == 0 {
		dlog.Debug("check local IP/port configuration")
	}

	lbStrategy := dns.DefaultLBStrategy
	switch strings.ToLower(config.LBStrategy) {
	case "":
		// default
	case "p2":
		lbStrategy = dns.LBStrategyP2
	case "ph":
		lbStrategy = dns.LBStrategyPH
	case "fastest":
	case "first":
		lbStrategy = dns.LBStrategyFirst
	case "random":
		lbStrategy = dns.LBStrategyRandom
	default:
		dlog.Warnf("unknown load balancing strategy: [%s]", config.LBStrategy)
	}
	proxy.ServersInfo = &dns.ServersInfo{}
	proxy.ServersInfo.LbStrategy = lbStrategy

	proxy.PluginBlockIPv6 = config.BlockIPv6
	proxy.PluginBlockUnqualified = config.BlockUnqualified
	proxy.Cache = config.Cache
	proxy.CacheSize = config.CacheSize

	if config.CacheNegTTL > 0 {
		proxy.CacheNegMinTTL = config.CacheNegTTL
		proxy.CacheNegMaxTTL = config.CacheNegTTL
	} else {
		proxy.CacheNegMinTTL = config.CacheNegMinTTL
		proxy.CacheNegMaxTTL = config.CacheNegMaxTTL
	}

	proxy.CacheMinTTL = config.CacheMinTTL
	proxy.CacheMaxTTL = config.CacheMaxTTL
	proxy.CloakTTL = config.CloakTTL

	proxy.QueryMeta = config.QueryMeta

	if len(config.QueryLog.Format) == 0 {
		config.QueryLog.Format = "tsv"
	} else {
		config.QueryLog.Format = strings.ToLower(config.QueryLog.Format)
	}
	if config.QueryLog.Format != "tsv" && config.QueryLog.Format != "ltsv" {
		return errors.New("Unsupported query log format")
	}
	proxy.QueryLogFile = config.QueryLog.File
	proxy.QueryLogFormat = config.QueryLog.Format
	proxy.QueryLogIgnoredQtypes = config.QueryLog.IgnoredQtypes

	if len(config.NxLog.Format) == 0 {
		config.NxLog.Format = "tsv"
	} else {
		config.NxLog.Format = strings.ToLower(config.NxLog.Format)
	}
	if config.NxLog.Format != "tsv" && config.NxLog.Format != "ltsv" {
		return errors.New("Unsupported NX log format")
	}
	proxy.NxLogFile = config.NxLog.File
	proxy.NxLogFormat = config.NxLog.Format

	if len(config.BlockName.Format) == 0 {
		config.BlockName.Format = "tsv"
	} else {
		config.BlockName.Format = strings.ToLower(config.BlockName.Format)
	}
	if config.BlockName.Format != "tsv" && config.BlockName.Format != "ltsv" {
		return errors.New("Unsupported block log format")
	}
	proxy.BlockNameFile = config.BlockName.File
	proxy.BlockNameFormat = config.BlockName.Format
	proxy.BlockNameLogFile = config.BlockName.LogFile

	proxy.CloakFile = config.CloakFile

	if configRoutes := config.AnonymizedDNS.Routes; configRoutes != nil {
		routes := make(map[string][]string)
		for _, configRoute := range configRoutes {
			routes[configRoute.ServerName] = configRoute.RelayNames
		}
		proxy.Routes = &routes
	}

	netprobeTimeout := config.NetprobeTimeout
	flag.Visit(func(flag *flag.Flag) {
		if flag.Name == "netprobe-Timeout" && flags.NetprobeTimeoutOverride != nil {
			netprobeTimeout = *flags.NetprobeTimeoutOverride
		}
	})
	netprobeAddress := DefaultNetprobeAddress
	if len(config.NetprobeAddress) > 0 {
		netprobeAddress = config.NetprobeAddress
	}
	
	if err := behaviors.NetProbe(netprobeAddress, proxy.LocalInterface, netprobeTimeout); err != nil {
		return err
	}
	if !config.OfflineMode {
		if err := config.loadSources(proxy); err != nil {
			return err
		}
		if len(proxy.RegisteredServers) == 0 {
			return errors.New("No servers configured")
		}
		config.loadTags(proxy)
		config.loadGroupsAssociation(proxy)
	}
	
	if proxy.Routes != nil && len(*proxy.Routes) > 0 {
		hasSpecificRoutes := false
		for _, server := range proxy.RegisteredServers {
			if via, ok := (*proxy.Routes)[server.Name]; ok {
				if server.Stamp.Proto != stamps.StampProtoTypeDNSCrypt {
					dlog.Errorf("DNS anonymization is only supported with the DNSCrypt protocol - Connections to [%v] cannot be anonymized", server.Name)
				} else {
					dlog.Noticef("anonymized DNS: routing [%v] via %v", server.Name, via)
				}
				hasSpecificRoutes = true
			}
		}
		if via, ok := (*proxy.Routes)[common.STAR]; ok {
			if hasSpecificRoutes {
				dlog.Noticef("anonymized DNS: routing everything else via %v", via)
			} else {
				dlog.Noticef("anonymized DNS: routing everything via %v", via)
			}
		}
	}
	if *flags.Check {
		dlog.Notice("configuration successfully checked")
		os.Exit(0)
	}
	return nil
}


func (config *Config) loadTags(proxy *dns.Proxy) {
	tags := make(map[string]map[string]interface{})
	for _, server := range proxy.RegisteredServers {
		for _, tag := range strings.Split(server.Stamp.Tags, common.Delimiter) {
			if servers, ok := tags[tag]; !ok {
				servers = make(map[string]interface{})
				servers[server.Name] = nil
				tags[tag] = servers
			} else {
				servers[server.Name] = nil
			}
		}
	}
	if len(tags) != 0 {
		proxy.Tags = &tags
	}
}

// Simplicity, Beauty, Complex, as Original Repurification
// panic if error, will migrate all critical cfg error to panic
func (config *Config) loadGroupsAssociation(proxy *dns.Proxy) {
	if len(config.Groups) == 0 || len(config.GroupsListener) == 0 {
		return
	}
	names := make(map[string]interface{})
	for _, server := range proxy.RegisteredServers {
		names[server.Name] = nil
	}
	var g = &conceptions.Graph{}
	regexNames := make([]string, 0)
	for _, group := range config.Groups {
		if len(group.Name) == 0 {
			panic("name of group must represent")
		}
		if len(group.Tag) != 0 {
			if len(group.Servers) != 0 {
				panic("tag or servers of " + group.Name + " group must be omitted")
			}
			hasTag := false
			if proxy.Tags != nil {
				if _, ok := (*proxy.Tags)[group.Tag]; ok {
					hasTag = true
				}
			}
			if !hasTag {
				panic("group tag " + group.Tag + " not found")
			}
		}
		if err := g.AddVertex(group.Name, group, group.Groups); err != nil {
			panic("group cfg has error:" + err.Error())
		}
		if len(group.Match) != 0 {
			regexNames = append(regexNames, group.Name)
		}
	}
	if err := g.Finalize(false); err != nil {
		panic("group cfg has error:" + err.Error())
	}
	positionLimit := len(proxy.ListenAddresses)
	listenerCfg := make(map[int]*dns.ListenerConfiguration)
	for _, gl := range config.GroupsListener {
		if gl.Position < 1 || gl.Position > positionLimit {
			panic("position of listener_association out of range, check listen_addresses")
		}
		if _, ok := listenerCfg[gl.Position]; ok {
			panic("duplicate position of listener_association")
		}
		
		if gl.Regex && len(gl.Group) != 0 {
			panic("group or regex is mutually exclusive in listener_association")
		}
		lc := dns.ListenerConfiguration{}
		getSvrs := func(groups []interface{}) *dns.Servers {
			svrs := dns.Servers{Priority:groups[0].(GroupsConfig).Priority}
			serverList := make(map[string]interface{})
			for _, group := range groups {
				gc := group.(GroupsConfig)
				for _, server := range gc.Servers {
					if server == common.STAR {
						for k, _ := range names {
							serverList[k] = nil
						}
						break
					}
					if _, ok := names[server]; !ok {
						panic("unknown server inside group:" + server)
					}
					if _, ok := serverList[server]; ok {
						continue
					}
					serverList[server] = nil
				}
				if len(gc.Tag) != 0 {
					for server, _ := range (*proxy.Tags)[gc.Tag] {
						if _, ok := serverList[server]; ok {
							continue
						}
						serverList[server] = nil
					}
				}
			}
			servers := make([]*string, 0)
			for server, _ := range serverList {
				svr := server
				servers = append(servers, &svr)
			}
			svrs.Servers = servers
			return &svrs
		}
		if !gl.Regex {
			if groups := g.Tags(gl.Group); groups != nil {
				svrs := getSvrs(groups)
				lc.ServerList = svrs
				dlog.Debugf("group mode actived for %s, root group is assigned to %s", proxy.ListenAddresses[gl.Position-1], gl.Group)
			} else {
				panic("group " + gl.Group + " not found in groups")
			}
		} else if len(regexNames) > 0 {
			gs := make(map[string]*dns.Servers)
			regexes := make([]string, len(regexNames))
			for i, name := range regexNames {
				groups := g.Tags(name);
				svrs := getSvrs(groups)
				regexes[i] = groups[0].(GroupsConfig).Match
				gs[name] = svrs
			}
			lc.Groups = &gs
			lc.Regex = services.CreateRegexBuilder(regexes, regexNames)
			dlog.Debugf("regex mode actived for %s, group count:%d", proxy.ListenAddresses[gl.Position-1], len(regexNames))

		} else {
			dlog.Warnf("position=%d, regex=true while zero match group found", gl.Position)
			continue
		}
		listenerCfg[gl.Position] = &lc
		
	}
	proxy.ListenerCfg = &listenerCfg
}

func (config *Config) loadSources(proxy *dns.Proxy) error {
	var requiredProps stamps.ServerInformalProperties
	if config.SourceRequireDNSSEC {
		requiredProps |= stamps.ServerInformalPropertyDNSSEC
	}
	if config.SourceRequireNoLog {
		requiredProps |= stamps.ServerInformalPropertyNoLog
	}
	if config.SourceRequireNoFilter {
		requiredProps |= stamps.ServerInformalPropertyNoFilter
	}
	for cfgSourceName, cfgSource := range config.SourcesConfig {
		if err := config.loadSource(proxy, requiredProps, cfgSourceName, &cfgSource); err != nil {
			return err
		}
	}
	if len(config.ServerNames) == 0 {
		for serverName := range config.StaticsConfig {
			config.ServerNames = append(config.ServerNames, serverName)
		}
	}
	for _, serverName := range config.ServerNames {
		staticConfig, ok := config.StaticsConfig[serverName]
		if !ok {
			continue
		}
		if len(staticConfig.Stamp) == 0 {
			dlog.Fatalf("missing stamp for the static [%s] definition", serverName)
		}
		stamp, err := stamps.NewServerStampFromString(staticConfig.Stamp)
		if err != nil {
			dlog.Fatalf("stamp error for the static [%s] definition: [%v]", serverName, err)
		}
		proxy.RegisteredServers = append(proxy.RegisteredServers, common.RegisteredServer{Name: serverName, Stamp: &stamp})
	}
	rand.Shuffle(len(proxy.RegisteredServers), func(i, j int) {
		proxy.RegisteredServers[i], proxy.RegisteredServers[j] = proxy.RegisteredServers[j], proxy.RegisteredServers[i]
	})

	return nil
}

func (config *Config) loadSource(proxy *dns.Proxy, requiredProps stamps.ServerInformalProperties, cfgSourceName string, cfgSource *SourceConfig) error {
	if len(cfgSource.URL) == 0 {
		dlog.Debugf("missing URLs for source [%s]", cfgSourceName)
	} else {
		dlog.Debugf("URLs are not working in this program [%s], however keep it for fun", cfgSourceName)
	}
	if cfgSource.MinisignKeyStr == "" {
		return dlog.Errorf("missing Minisign key for source [%s]", cfgSourceName)
	}
	if cfgSource.CacheFile == "" {
		return dlog.Errorf("missing cache file for source [%s]", cfgSourceName)
	}
	if cfgSource.FormatStr == "" {
		cfgSource.FormatStr = "v2"
	}
	if cfgSource.RefreshDelay <= 0 {
		cfgSource.RefreshDelay = 72
	}
	source, err := NewSource(cfgSourceName, proxy.XTransport, cfgSource.URLs, cfgSource.MinisignKeyStr, cfgSource.CacheFile, cfgSource.FormatStr, time.Duration(cfgSource.RefreshDelay)*time.Hour)
	if err != nil {
		dlog.Criticalf("failed to retrieve source [%s]: [%s]", cfgSourceName, err)
		return err
	}
	registeredServers, err := source.Parse(cfgSource.Prefix)
	if err != nil {
		if len(registeredServers) == 0 {
			dlog.Criticalf("failed to use source [%s]: [%s]", cfgSourceName, err)
			return err
		}
		dlog.Warnf("error in source [%s]: [%s] -- continuing with reduced server count [%d]", cfgSourceName, err, len(registeredServers))
	}
	for _, registeredserver := range registeredServers {
		if registeredserver.Stamp.Proto != stamps.StampProtoTypeDNSCryptRelay {
			if len(config.ServerNames) > 0 {
				if !includesName(config.ServerNames, registeredserver.Name) {
					continue
				}
			} else if registeredserver.Stamp.Props&requiredProps != requiredProps {
				continue
			}
		}
		if includesName(config.DisabledServerNames, registeredserver.Name) {
			continue
		}
		if config.SourceIPv4 || config.SourceIPv6 {
			isIPv4, isIPv6 := true, false
			if registeredserver.Stamp.Proto == stamps.StampProtoTypeDoH {
				isIPv4, isIPv6 = true, true
			}
			if strings.HasPrefix(registeredserver.Stamp.ServerAddrStr, "[") {
				isIPv4, isIPv6 = false, true
			}
			if !(config.SourceIPv4 == isIPv4 || config.SourceIPv6 == isIPv6) {
				continue
			}
		}
		if registeredserver.Stamp.Proto.String() == "Anonymized DNSCrypt" {
			dlog.Debugf("applying [%s] to the set of available relays", registeredserver.Name)
			proxy.RegisteredRelays = append(proxy.RegisteredRelays, registeredserver)
		} else {
			proto := registeredserver.Stamp.Proto.String()
			switch {
			case config.SourceDNSCrypt && proto == "DNSCrypt":
			case config.SourceDoH && proto == "DoH":
				if err := proxy.XTransport.BuildTransport(registeredserver, nil); err != nil {
					dlog.Fatal(err)
					return err;
				}
			case config.SourceDoT && proto == "DoT":
				if err := proxy.XTransport.BuildTLS(registeredserver); err != nil {
					dlog.Fatal(err)
					return err;
				}
			default:continue
			}
			dlog.Debugf("applying [%s] to the set of wanted resolvers", registeredserver.Name)
			proxy.RegisteredServers = append(proxy.RegisteredServers, registeredserver)
		}
	}
	return nil
}

func PrintInferfaceInfo(name *string) {
	dlog.Debug("++++++++++++++++Interfaces Info++++++++++++++++++++++++")
	if interfaces, err := net.Interfaces(); err == nil {
		for _, ifi := range interfaces {
			if ifi.Flags&net.FlagUp == 0 {
				continue
			}
			var selected string
			if name != nil && ifi.Name == *name {
				selected = "->"
			}
			dlog.Debugf("%s%s", selected, ifi.Name)
			addrs, _ := ifi.Addrs()
			var ip net.IP
			for _, addr1 := range addrs {
				switch v := addr1.(type) {
				case *net.IPAddr:
					ip = v.IP
				case *net.IPNet:
					ip = v.IP
				default:
					dlog.Debug(addr1)
				}
				var selected string
				if name != nil && ip.String() == *name {
					selected = "<-"
				}
				dlog.Debugf("%-28s LocalUnicast:%-5v GlobalUnicast:%-5v %s",
				addr1.String(), ip.IsLinkLocalUnicast(), ip.IsGlobalUnicast(), selected)
			}
		}
	}
	dlog.Debug("+++++++++++++++++++++++++++++++++++++++++++++++++++++++")
}

func includesName(names []string, name string) bool {
	for _, found := range names {
		if strings.EqualFold(found, name) {
			return true
		}
	}
	return false
}

func cdFileDir(fileName string) error {
	return os.Chdir(filepath.Dir(fileName))
}

func cdLocal() {
	exeFileName, err := os.Executable()
	if err != nil {
		dlog.Warnf("failed to determine the executable directory: [%s] -- You will need to specify absolute paths in the configuration file", err)
	} else if err = os.Chdir(filepath.Dir(exeFileName)); err != nil {
		dlog.Warnf("failed to change working directory to [%s]: %s", exeFileName, err)
	}
}
