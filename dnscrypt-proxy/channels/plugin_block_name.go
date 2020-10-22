package channels

import (
	"fmt"
	"strings"
	"time"

	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/services"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type PluginBlockName struct {
	matcher   *services.Regexp_builder
	logger    *lumberjack.Logger
	format    *string
}

func (plugin *PluginBlockName) Init(proxy *Proxy) error {
	dlog.Noticef("loading the set of blocking rules from [%s]", proxy.BlockNameFile)
	bin, err := common.ReadTextFile(proxy.BlockNameFile)
	if err != nil {
		return err
	}
	exps := make([]string, 0)
	for _, line := range strings.Split(string(bin), "\n") {
		line = common.TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		exps = append(exps, line)
	}
	proxy.pluginsGlobals.blockmatcher = services.CreateRegexBuilder(exps, nil)
	plugin.matcher = proxy.pluginsGlobals.blockmatcher
	if len(proxy.BlockNameLogFile) == 0 {
		return nil
	}
	proxy.pluginsGlobals.block_logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.LogMaxSize, MaxAge: proxy.LogMaxAge, MaxBackups: proxy.LogMaxBackups, Filename: proxy.BlockNameLogFile,}
	proxy.pluginsGlobals.block_format = &proxy.BlockNameFormat
	plugin.logger = proxy.pluginsGlobals.block_logger
	plugin.format = proxy.pluginsGlobals.block_format
	return nil
}

func (plugin *PluginBlockName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	blocked, err := check(plugin.matcher, plugin.logger, plugin.format, *pluginsState.qName, *pluginsState.qName)
	if blocked || err != nil {
		pluginsState.state = PluginsStateReject
	}
	return err
}

func check(matcher *services.Regexp_builder,logger *lumberjack.Logger,format *string, val string, qName string) (_ bool, err error) {
	if matcher.MatchString(val) {
		if logger != nil {
			var line string
			switch *format {
				case "tsv":
					now := time.Now()
					year, month, day := now.Date()
					hour, minute, second := now.Clock()
					tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
					line = fmt.Sprintf("%s\t%s\t%s\n", tsStr, common.StringQuote(val), common.StringQuote(qName))
				case "ltsv":
					line = fmt.Sprintf("time:%d\thost:%s\tqname:%s\n", time.Now().Unix(), common.StringQuote(val), common.StringQuote(qName))
				default:
					dlog.Fatalf("unexpected log format: [%s]", format)
			}
			_, err = logger.Write([]byte(line))
		}
		return true, err
	}
	return false, err
}

// ---

type PluginBlockNameResponse struct {
	matcher   *services.Regexp_builder
	logger    *lumberjack.Logger
	format    *string
}

func (plugin *PluginBlockNameResponse) Init(proxy *Proxy) error {
	plugin.matcher = proxy.pluginsGlobals.blockmatcher
	plugin.logger = proxy.pluginsGlobals.block_logger
	plugin.format = proxy.pluginsGlobals.block_format
	return nil
}

func (plugin *PluginBlockNameResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	for _, answer := range msg.Answer {
		header := answer.Header()
		if header.Class != dns.ClassINET || header.Rrtype != dns.TypeCNAME {
			continue
		}
		target, err := common.NormalizeQName(answer.(*dns.CNAME).Target)
		if err != nil {
			return err
		}
		if blocked, err := check(plugin.matcher, plugin.logger, plugin.format, target, *pluginsState.qName); blocked || err != nil {
			pluginsState.state = PluginsStateReject
			return err
		}
	}
	return nil
}
