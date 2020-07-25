package main

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"context"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
	stamps "stammel"
	"golang.org/x/sync/semaphore"
)

const (
	MaxTimeout             = 43200
	DefaultNetprobeAddress = "127.0.0.1:53"
)

type Config struct {

	Daemonize                bool
	Cache                    bool
	LogLevel                 int                         `toml:"log_level"`
	LogFile                  *string                     `toml:"log_file"`
	UseSyslog                bool                        `toml:"use_syslog"`
	ServerNames              []string                    `toml:"server_names"`
	DisabledServerNames      []string                    `toml:"disabled_server_names"`
	ListenAddresses          []string                    `toml:"listen_addresses"`
	UserName                 string                      `toml:"user_name"`
	ForceTCP                 bool                        `toml:"force_tcp"`
	Timeout                  int                         `toml:"timeout"`
	KeepAlive                int                         `toml:"keepalive"`
	CertRefreshDelay         int                         `toml:"cert_refresh_delay"`
	CertIgnoreTimestamp      bool                        `toml:"cert_ignore_timestamp"`
	EphemeralKeys            bool                        `toml:"dnscrypt_ephemeral_keys"`
	LBStrategy               string                      `toml:"lb_strategy"`
	BlockIPv6                bool                        `toml:"block_ipv6"`
	BlockUnqualified         bool                        `toml:"block_unqualified"`
	BlockUndelegated         bool                        `toml:"block_undelegated"`
	CacheSize                int                         `toml:"cache_size"`
	CacheNegTTL              uint32                      `toml:"cache_neg_ttl"`
	CacheNegMinTTL           uint32                      `toml:"cache_neg_min_ttl"`
	CacheNegMaxTTL           uint32                      `toml:"cache_neg_max_ttl"`
	CacheMinTTL              uint32                      `toml:"cache_min_ttl"`
	CacheMaxTTL              uint32                      `toml:"cache_max_ttl"`
	RejectTTL                uint32                      `toml:"reject_ttl"`
	CloakTTL                 uint32                      `toml:"cloak_ttl"`
	QueryLog                 QueryLogConfig              `toml:"query_log"`
	NxLog                    NxLogConfig                 `toml:"nx_log"`
	BlockName                BlockNameConfig             `toml:"blacklist"`
	WhitelistName            WhitelistNameConfig         `toml:"whitelist"`
	CloakFile                string                      `toml:"cloaking_rules"`
	StaticsConfig            map[string]StaticConfig     `toml:"static"`
	SourcesConfig            map[string]SourceConfig     `toml:"sources"`
	BrokenImplementations    BrokenImplementationsConfig `toml:"broken_implementations"`
	SourceRequireDNSSEC      bool                        `toml:"require_dnssec"`
	SourceRequireNoLog       bool                        `toml:"require_nolog"`
	SourceRequireNoFilter    bool                        `toml:"require_nofilter"`
	SourceDNSCrypt           bool                        `toml:"dnscrypt_servers"`
	SourceDoH                bool                        `toml:"doh_servers"`
	SourceDoT                bool                        `toml:"dot_servers"`
	SourceIPv4               bool                        `toml:"ipv4_servers"`
	SourceIPv6               bool                        `toml:"ipv6_servers"`
	MaxClients               uint32                      `toml:"max_clients"`
	LogMaxSize               int                         `toml:"log_files_max_size"`
	LogMaxAge                int                         `toml:"log_files_max_age"`
	LogMaxBackups            int                         `toml:"log_files_max_backups"`
	TLSDisableSessionTickets bool                        `toml:"tls_disable_session_tickets"`
	TLSCipherSuite           []uint16                    `toml:"tls_cipher_suite"`
	NetprobeAddress          string                      `toml:"netprobe_address"`
	NetprobeTimeout          int                         `toml:"netprobe_timeout"`
	OfflineMode              bool                        `toml:"offline_mode"`
	ProxyURI                 string                      `toml:"proxy_uri"`
	ProxyIP                  string                      `toml:"proxy_ip"`
	BlockedQueryResponse     string                      `toml:"blocked_query_response"`
	QueryMeta                []string                    `toml:"query_meta"`
	AnonymizedDNS            AnonymizedDNSConfig         `toml:"anonymized_dns"`
}

func newConfig() Config {
	return Config{
		LogLevel:                 int(dlog.LogLevel()),
		ListenAddresses:          []string{"127.0.0.1:53"},
		Timeout:                  5000,
		KeepAlive:                5,
		CertRefreshDelay:         240,
		CertIgnoreTimestamp:      false,
		EphemeralKeys:            false,
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
		TLSCipherSuite:           nil,
		NetprobeTimeout:          60,
		OfflineMode:              false,
		BlockedQueryResponse:     "hinfo",
		BrokenImplementations: BrokenImplementationsConfig{
			BrokenQueryPadding: []string{"cisco", "cisco-ipv6", "cisco-familyshield", "quad9-dnscrypt-ip4-filter-alt", "quad9-dnscrypt-ip4-filter-pri", "quad9-dnscrypt-ip4-nofilter-alt", "quad9-dnscrypt-ip4-nofilter-pri", "quad9-dnscrypt-ip6-filter-alt", "quad9-dnscrypt-ip6-filter-pri", "quad9-dnscrypt-ip6-nofilter-alt", "quad9-dnscrypt-ip6-nofilter-pri"},
		},
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

type WhitelistNameConfig struct {
	File    string `toml:"whitelist_file"`
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

type BrokenImplementationsConfig struct {
	BrokenQueryPadding []string `toml:"broken_query_padding"`
}

type ServerSummary struct {
	Name        string   `json:"name"`
	Proto       string   `json:"proto"`
	IPv6        bool     `json:"ipv6"`
	Addrs       []string `json:"addrs,omitempty"`
	Ports       []int    `json:"ports"`
	DNSSEC      bool     `json:"dnssec"`
	NoLog       bool     `json:"nolog"`
	NoFilter    bool     `json:"nofilter"`
	Stamp       string   `json:"stamp"`
}

type ConfigFlags struct {
	Check                   *bool
	ConfigFile              *string
	Child                   *bool
	NetprobeTimeoutOverride *int
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

func ConfigLoad(proxy *Proxy, flags *ConfigFlags) error {
	foundConfigFile, err := findConfigFile(flags.ConfigFile)
	if err != nil {
		dlog.Fatalf("failed to load the configuration file [%s]", *flags.ConfigFile)
	}
	config := newConfig()
	md, err := toml.DecodeFile(foundConfigFile, &config)
	if err != nil {
		return err
	}
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return fmt.Errorf("Unsupported key in configuration file: [%s]", undecoded[0])
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
			FileDescriptors = append(FileDescriptors, dlog.GetFileDescriptor())
		} else {
			FileDescriptorNum++
			dlog.SetFileDescriptor(os.NewFile(uintptr(3), "logFile"))
		}
	}
	dlog.Noticef("dnscrypt-proxy %s built with %s", AppVersion, runtime.Version())
	dlog.Noticef("LogLevel %s", dlog.SeverityName[dlog.LogLevel()])
	proxy.userName = config.UserName
	proxy.child = *flags.Child
	
	proxy.listenAddresses = config.ListenAddresses
	
	if !*flags.Child && len(proxy.userName) > 0 && !*flags.Check {
		return nil
	}
	
	proxy.logMaxSize = config.LogMaxSize
	proxy.logMaxAge = config.LogMaxAge
	proxy.logMaxBackups = config.LogMaxBackups


	proxy.xTransport = NewXTransport()
	proxy.xTransport.tlsDisableSessionTickets = config.TLSDisableSessionTickets
	proxy.xTransport.tlsCipherSuite = config.TLSCipherSuite
	proxy.xTransport.keepAlive = time.Duration(config.KeepAlive) * time.Second
	proxy.xTransport.transports = make(map[string]*TransportHolding)
	if len(config.ProxyURI) > 0 {
		globalProxy, err := url.Parse(config.ProxyURI)
		if err != nil {
			dlog.Fatalf("failed to parse the proxy URL [%v]", config.ProxyURI)
		}
		proxy.xTransport.Proxies = InitProxies()
		var ep *Endpoint
		if len(config.ProxyIP) > 0 {
			
			if ep, err = ResolveEndpoint(config.ProxyIP); err !=nil {
				dlog.Fatalf("failed to parse the proxy IP [%v]", config.ProxyIP)
			}
		}
		proxy.xTransport.Proxies.AddGlobalProxy(globalProxy, ep)
	}

	proxy.blockedQueryResponse = config.BlockedQueryResponse
	proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.maxClients = config.MaxClients
	proxy.smaxClients = semaphore.NewWeighted(int64(proxy.maxClients))
	proxy.ctx, proxy.cancel = context.WithCancel(context.Background())
	proxy.mainProto = "udp"
	if config.ForceTCP {
		proxy.mainProto = "tcp"
	}
	dlog.Noticef("dnscrypt-protocol bind to %s", proxy.mainProto)
	proxy.certRefreshDelay = time.Duration(Max(60, config.CertRefreshDelay)) * time.Minute
	proxy.certIgnoreTimestamp = config.CertIgnoreTimestamp
	proxy.ephemeralKeys = config.EphemeralKeys
	if len(config.ListenAddresses) == 0 {
		dlog.Debug("check local IP/port configuration")
	}

	lbStrategy := DefaultLBStrategy
	switch strings.ToLower(config.LBStrategy) {
	case "":
		// default
	case "p2":
		lbStrategy = LBStrategyP2
	case "ph":
		lbStrategy = LBStrategyPH
	case "fastest":
	case "first":
		lbStrategy = LBStrategyFirst
	case "random":
		lbStrategy = LBStrategyRandom
	default:
		dlog.Warnf("unknown load balancing strategy: [%s]", config.LBStrategy)
	}
	proxy.serversInfo.lbStrategy = lbStrategy

	proxy.daemonize = config.Daemonize
	proxy.pluginBlockIPv6 = config.BlockIPv6
	proxy.pluginBlockUnqualified = config.BlockUnqualified
	proxy.pluginBlockUndelegated = config.BlockUndelegated
	proxy.cache = config.Cache
	proxy.cacheSize = config.CacheSize

	if config.CacheNegTTL > 0 {
		proxy.cacheNegMinTTL = config.CacheNegTTL
		proxy.cacheNegMaxTTL = config.CacheNegTTL
	} else {
		proxy.cacheNegMinTTL = config.CacheNegMinTTL
		proxy.cacheNegMaxTTL = config.CacheNegMaxTTL
	}

	proxy.cacheMinTTL = config.CacheMinTTL
	proxy.cacheMaxTTL = config.CacheMaxTTL
	proxy.rejectTTL = config.RejectTTL
	proxy.cloakTTL = config.CloakTTL

	proxy.queryMeta = config.QueryMeta

	if len(config.QueryLog.Format) == 0 {
		config.QueryLog.Format = "tsv"
	} else {
		config.QueryLog.Format = strings.ToLower(config.QueryLog.Format)
	}
	if config.QueryLog.Format != "tsv" && config.QueryLog.Format != "ltsv" {
		return errors.New("Unsupported query log format")
	}
	proxy.queryLogFile = config.QueryLog.File
	proxy.queryLogFormat = config.QueryLog.Format
	proxy.queryLogIgnoredQtypes = config.QueryLog.IgnoredQtypes

	if len(config.NxLog.Format) == 0 {
		config.NxLog.Format = "tsv"
	} else {
		config.NxLog.Format = strings.ToLower(config.NxLog.Format)
	}
	if config.NxLog.Format != "tsv" && config.NxLog.Format != "ltsv" {
		return errors.New("Unsupported NX log format")
	}
	proxy.nxLogFile = config.NxLog.File
	proxy.nxLogFormat = config.NxLog.Format

	if len(config.BlockName.Format) == 0 {
		config.BlockName.Format = "tsv"
	} else {
		config.BlockName.Format = strings.ToLower(config.BlockName.Format)
	}
	if config.BlockName.Format != "tsv" && config.BlockName.Format != "ltsv" {
		return errors.New("Unsupported block log format")
	}
	proxy.blockNameFile = config.BlockName.File
	proxy.blockNameFormat = config.BlockName.Format
	proxy.blockNameLogFile = config.BlockName.LogFile

	if len(config.WhitelistName.Format) == 0 {
		config.WhitelistName.Format = "tsv"
	} else {
		config.WhitelistName.Format = strings.ToLower(config.WhitelistName.Format)
	}
	if config.WhitelistName.Format != "tsv" && config.WhitelistName.Format != "ltsv" {
		return errors.New("Unsupported whitelist log format")
	}
	proxy.whitelistNameFile = config.WhitelistName.File
	proxy.whitelistNameFormat = config.WhitelistName.Format
	proxy.whitelistNameLogFile = config.WhitelistName.LogFile

	proxy.cloakFile = config.CloakFile

	if configRoutes := config.AnonymizedDNS.Routes; configRoutes != nil {
		routes := make(map[string][]string)
		for _, configRoute := range configRoutes {
			routes[configRoute.ServerName] = configRoute.RelayNames
		}
		proxy.routes = &routes
	}
	proxy.serversWithBrokenQueryPadding = config.BrokenImplementations.BrokenQueryPadding

	netprobeTimeout := config.NetprobeTimeout
	flag.Visit(func(flag *flag.Flag) {
		if flag.Name == "netprobe-timeout" && flags.NetprobeTimeoutOverride != nil {
			netprobeTimeout = *flags.NetprobeTimeoutOverride
		}
	})
	netprobeAddress := DefaultNetprobeAddress
	if len(config.NetprobeAddress) > 0 {
		netprobeAddress = config.NetprobeAddress
	}
	
	if err := NetProbe(netprobeAddress, netprobeTimeout); err != nil {
		return err
	}
	if !config.OfflineMode {
		if err := config.loadSources(proxy); err != nil {
			return err
		}
		if len(proxy.registeredServers) == 0 {
			return errors.New("No servers configured")
		}
	}
	
	if proxy.routes != nil && len(*proxy.routes) > 0 {
		hasSpecificRoutes := false
		for _, server := range proxy.registeredServers {
			if via, ok := (*proxy.routes)[server.name]; ok {
				if server.stamp.Proto != stamps.StampProtoTypeDNSCrypt {
					dlog.Errorf("DNS anonymization is only supported with the DNSCrypt protocol - Connections to [%v] cannot be anonymized", server.name)
				} else {
					dlog.Noticef("anonymized DNS: routing [%v] via %v", server.name, via)
				}
				hasSpecificRoutes = true
			}
		}
		if via, ok := (*proxy.routes)["*"]; ok {
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

func (config *Config) loadSources(proxy *Proxy) error {
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
		proxy.registeredServers = append(proxy.registeredServers, RegisteredServer{name: serverName, stamp: &stamp})
	}
	rand.Shuffle(len(proxy.registeredServers), func(i, j int) {
		proxy.registeredServers[i], proxy.registeredServers[j] = proxy.registeredServers[j], proxy.registeredServers[i]
	})

	return nil
}

func (config *Config) loadSource(proxy *Proxy, requiredProps stamps.ServerInformalProperties, cfgSourceName string, cfgSource *SourceConfig) error {
	if len(cfgSource.URLs) == 0 {
		if len(cfgSource.URL) == 0 {
			dlog.Debugf("missing URLs for source [%s]", cfgSourceName)
		} else {
			cfgSource.URLs = []string{cfgSource.URL}
		}
	}
	if cfgSource.MinisignKeyStr == "" {
		return fmt.Errorf("missing Minisign key for source [%s]", cfgSourceName)
	}
	if cfgSource.CacheFile == "" {
		return fmt.Errorf("missing cache file for source [%s]", cfgSourceName)
	}
	if cfgSource.FormatStr == "" {
		cfgSource.FormatStr = "v2"
	}
	if cfgSource.RefreshDelay <= 0 {
		cfgSource.RefreshDelay = 72
	}
	source, err := NewSource(cfgSourceName, proxy.xTransport, cfgSource.URLs, cfgSource.MinisignKeyStr, cfgSource.CacheFile, cfgSource.FormatStr, time.Duration(cfgSource.RefreshDelay)*time.Hour)
	if err != nil {
		dlog.Criticalf("failed to retrieve source [%s]: [%s]", cfgSourceName, err)
		return err
	}
	proxy.sources = append(proxy.sources, source)
	registeredServers, err := source.Parse(cfgSource.Prefix)
	if err != nil {
		if len(registeredServers) == 0 {
			dlog.Criticalf("failed to use source [%s]: [%s]", cfgSourceName, err)
			return err
		}
		dlog.Warnf("error in source [%s]: [%s] -- Continuing with reduced server count [%d]", cfgSourceName, err, len(registeredServers))
	}
	for _, registeredServer := range registeredServers {
		if registeredServer.stamp.Proto != stamps.StampProtoTypeDNSCryptRelay {
			if len(config.ServerNames) > 0 {
				if !includesName(config.ServerNames, registeredServer.name) {
					continue
				}
			} else if registeredServer.stamp.Props&requiredProps != requiredProps {
				continue
			}
		}
		if includesName(config.DisabledServerNames, registeredServer.name) {
			continue
		}
		if config.SourceIPv4 || config.SourceIPv6 {
			isIPv4, isIPv6 := true, false
			if registeredServer.stamp.Proto == stamps.StampProtoTypeDoH {
				isIPv4, isIPv6 = true, true
			}
			if strings.HasPrefix(registeredServer.stamp.ServerAddrStr, "[") {
				isIPv4, isIPv6 = false, true
			}
			if !(config.SourceIPv4 == isIPv4 || config.SourceIPv6 == isIPv6) {
				continue
			}
		}
		if registeredServer.stamp.Proto.String() == "Anonymized DNSCrypt" {
			dlog.Debugf("applying [%s] to the set of available relays", registeredServer.name)
			proxy.registeredRelays = append(proxy.registeredRelays, registeredServer)
		} else {
			proto := registeredServer.stamp.Proto.String()
			switch {
			case config.SourceDNSCrypt && proto == "DNSCrypt":
			case config.SourceDoH && proto == "DoH":
				if err := proxy.xTransport.buildTransport(registeredServer, nil); err != nil {
					dlog.Fatal(err)
					return err;
				}
			case config.SourceDoT && proto == "DoT":
				if err := proxy.xTransport.buildTLS(registeredServer); err != nil {
					dlog.Fatal(err)
					return err;
				}
			default:continue
			}
			dlog.Debugf("applying [%s] to the set of wanted resolvers", registeredServer.name)
			proxy.registeredServers = append(proxy.registeredServers, registeredServer)
		}
	}
	return nil
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
