package channels

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type PluginQueryLog struct {
	logger        *lumberjack.Logger
	format        string
	ignoredQtypes []string
}

func (plugin *PluginQueryLog) Init(proxy *Proxy) error {
	plugin.logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.LogMaxSize, MaxAge: proxy.LogMaxAge, MaxBackups: proxy.LogMaxBackups, Filename: proxy.QueryLogFile,}
	plugin.format = proxy.QueryLogFormat
	plugin.ignoredQtypes = proxy.QueryLogIgnoredQtypes

	return nil
}

func (plugin *PluginQueryLog) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	qType, ok := dns.TypeToString[question.Qtype]
	if !ok {
		qType = string(qType)
	}
	if len(plugin.ignoredQtypes) > 0 {
		for _, ignoredQtype := range plugin.ignoredQtypes {
			if strings.EqualFold(ignoredQtype, qType) {
				return nil
			}
		}
	}
	var clientIPStr string
	if *(pluginsState.clientProto) == "udp" {
		clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
	} else {
		clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
	}
	qName := *(pluginsState.qName)
	if pluginsState.cacheHit {
		pluginsState.serverName = nil
	} else {
		switch pluginsState.returnCode {
		case PluginsReturnCodeSynth, PluginsReturnCodeCloak, PluginsReturnCodeParseError:
			pluginsState.serverName = nil
		}
	}
	returnCode, ok := PluginsReturnCodeToString[pluginsState.returnCode]
	if !ok {
		returnCode = string(returnCode)
	}

	var requestDuration time.Duration
	if !pluginsState.requestStart.IsZero() && !pluginsState.requestEnd.IsZero() {
		requestDuration = pluginsState.requestEnd.Sub(pluginsState.requestStart)
	}
	var line string
	if plugin.format == "tsv" {
		now := time.Now()
		year, month, day := now.Date()
		hour, minute, second := now.Clock()
		tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
		line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%dms\t%s\n", tsStr, clientIPStr, common.StringQuote(qName), qType, returnCode, requestDuration/time.Millisecond,
			common.StringQuote(pluginsState.ServerName()))
	} else if plugin.format == "ltsv" {
		Cached := 0
		if pluginsState.cacheHit {
			Cached = 1
		}
		line = fmt.Sprintf("time:%d\thost:%s\tmessage:%s\ttype:%s\treturn:%s\tCached:%d\tduration:%d\tserver:%s\n",
			time.Now().Unix(), clientIPStr, common.StringQuote(qName), qType, returnCode, Cached, requestDuration/time.Millisecond, common.StringQuote(pluginsState.ServerName()))
	} else {
		dlog.Fatalf("unexpected log format: [%s]", plugin.format)
	}
	if plugin.logger == nil {
		return errors.New("Log file not initialized")
	}
	_, _ = plugin.logger.Write([]byte(line))

	return nil
}
