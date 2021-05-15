package configuration

import (
	"crypto/sha256"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"runtime"

	"github.com/AZ-X/pique/repique/behaviors"
	"github.com/AZ-X/pique/repique/features/dns"
	"github.com/AZ-X/pique/repique/features/dns/channels"
	"github.com/AZ-X/pique/repique/features/dns/nodes"
	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/conceptions"
	"github.com/AZ-X/pique/repique/services"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"

	stamps "github.com/AZ-X/pique/repique/unclassified/stammel"
)

const (
)

type Config struct {
	*Main
	NodesSections            nodes.Config                  `toml:"dns_nodes"`
	ChannelsSections         map[string]channels.Config    `toml:"channels_sections"`
	SourcesConfig            map[string]nodes.SourceConfig `toml:"sources"`
	AnonymizedDNS            *nodes.AnonymizedDNSConfig    `toml:"anonymized_dns"`
}

type Main struct {
	LogLevel                 int                           `toml:"log_level"`
	LogFile                  *string                       `toml:"log_file"`
	UseSyslog                bool                          `toml:"use_syslog"`
	NetprobeTimeout          int                           `toml:"netprobe_Timeout"`
	ListenAddresses          []string                      `toml:"listen_addresses"`
	ProxyURI                 string                        `toml:"proxy_uri"`
	ProxyIP                  string                        `toml:"proxy_ip"`
	LocalInterface           string                        `toml:"network_interface"`
	NetprobeAddress          string                        `toml:"netprobe_address"`
	UserName                 string                        `toml:"user_name"`
	Groups                   []GroupsConfig                `toml:"groups"`
	GroupsListener           []ListenerAssociation         `toml:"listener_association"`
}

type GroupsConfig struct {
	Name           string   `toml:"name"`
	Servers        []string `toml:"servers"`
	Tag            string   `toml:"tag"`
	Groups         []string `toml:"groups"`
	Priority       bool     `toml:"priority"`
	Match          string   `toml:"match"`
	DNSSEC         bool     `toml:"dnssec"`
}

type ListenerAssociation struct {
	Position       int      `toml:"position"`
	Group          string   `toml:"group"`
	Regex          bool     `toml:"regex"`
	DNSSEC         bool     `toml:"dnssec"`
}

type ConfigFlags struct {
	Check                   *bool
	ConfigFile              *string
	Child                   *bool
}

func findConfigFile(configFile *string) (string, error) {
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		if exeFileName, err := os.Executable(); err != nil {
			dlog.Warnf("failed to determine the executable directory: [%s] -- You will need to specify absolute paths in the configuration file", err)
		} else if err = os.Chdir(filepath.Dir(exeFileName)); err != nil {
			dlog.Warnf("failed to change working directory to [%s]: %s", exeFileName, err)
		}
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
		panic("failed to load the configuration file " + *flags.ConfigFile)
	}
	config := &Config{}
	proxy.ProxyStartup = &dns.ProxyStartup{}
	md, err := toml.DecodeFile(foundConfigFile, config)
	if err != nil {
		return err
	}
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return dlog.Errorf("Unsupported key in configuration file: [%s]", undecoded[0])
	}
	if err := os.Chdir(filepath.Dir(foundConfigFile)); err != nil {
		return err
	}
	if config.LogLevel >= 0 && config.LogLevel <= int(dlog.SeverityError) {
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
	dlog.Noticef("repique %s built with runtime+stdlib %s on %s arch=%s",
	common.AppVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	dlog.Noticef("LogLevel %s", dlog.SeverityName[dlog.LogLevel()])
	proxy.UserName = config.UserName
	proxy.Child = *flags.Child
	if len(config.ListenAddresses) == 0 {
		panic("check local IP/port configuration")
	}
	proxy.ListenAddresses = config.ListenAddresses
	
	if !*flags.Child && len(proxy.UserName) > 0 && !*flags.Check {
		return nil
	}
	var ifi *string
	if len(config.LocalInterface) > 0 {
		ifi = &config.LocalInterface
	}
	if config.LogLevel == int(dlog.SeverityDebug) {
		printInferfaceInfo(ifi)
	}

	if !*flags.Check {
		if err := behaviors.NetProbe(config.NetprobeAddress, ifi, config.NetprobeTimeout); err != nil {
			return err
		}
	}

	var np *conceptions.NestedProxy
	if len(config.ProxyURI) > 0 {
		globalProxy, err := url.Parse(config.ProxyURI)
		if err != nil {
			panic("failed to parse the URL of proxy -> " + config.ProxyURI)
		}
		np = conceptions.InitProxies()
		var ep *common.Endpoint
		if len(config.ProxyIP) > 0 {
			
			if ep, err = common.ResolveEndpoint(config.ProxyIP); err !=nil {
				panic("failed to parse the ip-port of proxy -> " + config.ProxyIP)
			}
		}
		np.AddGlobalProxy(globalProxy, ep)
	}
	proxy.NodesMgr = &nodes.NodesMgr{}
	if servers, relays, proxies, sum, err := config.loadNodes(proxy); err != nil {
		return err
	} else {
		dnssec := false
		config.loadTags(proxy, servers)
		config.loadGroupsAssociation(proxy, servers, &dnssec)
		config.loadChannels(proxy, dnssec)
		proxy.NodesMgr.Init(&config.NodesSections, config.AnonymizedDNS, sum, servers, relays, proxies, np, ifi)
	}
	proxy.Timeout = time.Duration(config.NodesSections.Timeout) * time.Second

	if *flags.Check {
		dlog.Notice("configuration successfully checked")
		os.Exit(0)
	}
	return nil
}

func (_ *Config) loadTags(proxy *dns.Proxy, _servers map[string]*common.RegisteredServer) {
	tags := make(map[string]map[string]interface{})
	for _, server := range _servers {
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
func (config *Config) loadGroupsAssociation(proxy *dns.Proxy, _servers map[string]*common.RegisteredServer, dnssec *bool) {
	if len(config.Groups) == 0 || len(config.GroupsListener) == 0 {
		return
	}
	names := make(map[string]interface{})
	for _, server := range _servers {
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
	listenerCfg := make([]*nodes.ListenerConfiguration, len(config.GroupsListener) + 1)
	for _, gl := range config.GroupsListener {
		if gl.Position < 1 || gl.Position > positionLimit {
			panic("position of listener_association out of range, check listen_addresses")
		}
		if listenerCfg[gl.Position] != nil {
			panic("duplicate position of listener_association")
		}
		
		if gl.Regex && len(gl.Group) != 0 {
			panic("group or regex is mutually exclusive in listener_association")
		}
		lc := nodes.ListenerConfiguration{}
		lc.DNSSEC = gl.DNSSEC
		if gl.DNSSEC {
			*dnssec = true
		}
		getSvrs := func(groups []interface{}) *nodes.Servers {
			svrs := nodes.Servers{Priority:groups[0].(GroupsConfig).Priority, DNSSEC:groups[0].(GroupsConfig).DNSSEC,}
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
			gs := make(map[string]*nodes.Servers)
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
	proxy.L2NMapping = &listenerCfg
}

const CFG_Channels_Main = "main"
const CFG_Channels_SP = "sp"
func (config *Config) loadChannels(proxy *dns.Proxy, dnssec bool) {
	proxy.ChannelMgr = &channels.ChannelMgr{}
	proxy.ChannelMgr.Init(len(config.ListenAddresses))
	var individual, shares []int
	for idx, la := range config.ListenAddresses {
		if cfg, ok := config.ChannelsSections[la]; ok {
			proxy.ChannelMgr.Cfgs[idx+1] = &cfg
			individual = append(individual, idx+1)
		} else {
			if cfg, ok := config.ChannelsSections[CFG_Channels_Main]; ok {
				proxy.ChannelMgr.Cfgs[idx+1] = &cfg
				shares = append(shares, idx+1)
			} else {
				panic("missing main cfg for channels")
			}
		}
	}
	if config.NodesSections.Bootstrap || dnssec {
		if cfg, ok := config.ChannelsSections[CFG_Channels_SP]; ok {
			proxy.ChannelMgr.Cfgs[0] = &cfg
		} else if cfg, ok = config.ChannelsSections[CFG_Channels_Main]; ok {
			proxy.ChannelMgr.Cfgs[0] = &cfg
		} else {
			panic("missing sp or main cfg for bootstrap or dnssec")
		}
		shares = append(shares, 0)
		if proxy.L2NMapping == nil {
			m := make([]*nodes.ListenerConfiguration, 1)
			proxy.L2NMapping = &m
		}
	}
	proxy.ChannelMgr.InitChannels(individual, shares)
}

func (config *Config) loadNodes(proxy *dns.Proxy) (servers, relays, proxies map[string]*common.RegisteredServer, sum []byte, err error) {
	hasher := sha256.New()
	servers = make(map[string]*common.RegisteredServer)
	relays = make(map[string]*common.RegisteredServer)
	proxies = make(map[string]*common.RegisteredServer)
	for cfgSourceName, cfgSource := range config.SourcesConfig {
		if len(cfgSource.URL) == 0 {
			dlog.Debugf("missing URLs for source [%s], it's all right", cfgSourceName)
		} else {
			dlog.Debugf("source [%s] - URLs are not working in this program , however keep it for fun", cfgSourceName)
		}
		if cfgSource.MinisignKeyStr == "" {
			return nil, nil, nil, nil, dlog.Errorf("missing Minisign key for source [%s]", cfgSourceName)
		}
		if cfgSource.CacheFile == "" {
			return nil, nil, nil, nil, dlog.Errorf("missing customized file for your own source [%s]", cfgSourceName)
		}
		if cfgSource.RefreshDelay <= 0 {
			cfgSource.RefreshDelay = 72
		}
		source, err := NewSource(cfgSourceName, cfgSource.URLs, cfgSource.MinisignKeyStr, cfgSource.CacheFile, time.Duration(cfgSource.RefreshDelay)*time.Hour)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		registeredServers, err := source.Parse(cfgSource.Prefix, hasher)
		if err != nil {
			if len(registeredServers) == 0 {
				return nil, nil, nil, nil, err
			}
			dlog.Warnf("error in source [%s]: [%s] -- continuing with reduced server count [%d]", cfgSourceName, err, len(registeredServers))
		}
		includesName := func(names []string, name string) bool {
			for _, found := range names {
				if strings.EqualFold(found, name) {
					return true
				}
			}
			return false
		}
		for _, server := range registeredServers {
			if server.Stamp.Proto != stamps.StampProtoTypeDNSCryptRelay {
				if len(config.NodesSections.ServerNames) > 0 {
					if !includesName(config.NodesSections.ServerNames, server.Name) {
						continue
					}
				}
			}
			if includesName(config.NodesSections.DisabledServerNames, server.Name) {
				continue
			}
			switch server.Stamp.Proto.String() {
				case "Anonymized DNSCrypt": relays[server.Name] = server
					dlog.Debugf("applying relay [%s]", server.Name)
				case "Proxy": proxies[server.Name] = server
					dlog.Debugf("applying proxy [%s]", server.Name)
				default: servers[server.Name] = server
					dlog.Debugf("applying nodes [%s]", server.Name)
			}
		}
	}
	return servers, relays, proxies, hasher.Sum(nil), nil
}

func printInferfaceInfo(name *string) {
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
