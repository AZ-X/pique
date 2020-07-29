package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type PluginWhitelistName struct {
	patternMatcher  *PatternMatcher
	logger          *lumberjack.Logger
	format          string
}

func (plugin *PluginWhitelistName) Init(proxy *Proxy) error {
	dlog.Noticef("loading the set of whitelisting rules from [%s]", proxy.whitelistNameFile)
	bin, err := ReadTextFile(proxy.whitelistNameFile)
	if err != nil {
		return err
	}
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, "@")
		if len(parts) > 1 {
			dlog.Errorf("syntax error in whitelist rules at line %d -- Unexpected @ character", 1+lineNo)
			continue
		}
		if err := plugin.patternMatcher.Add(line, nil, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}
	if len(proxy.whitelistNameLogFile) == 0 {
		return nil
	}
	plugin.logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.logMaxSize, MaxAge: proxy.logMaxAge, MaxBackups: proxy.logMaxBackups, Filename: proxy.whitelistNameLogFile, Compress: true}
	plugin.format = proxy.whitelistNameFormat

	return nil
}

func (plugin *PluginWhitelistName) Drop() error {
	return nil
}

func (plugin *PluginWhitelistName) Reload() error {
	return nil
}

func (plugin *PluginWhitelistName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	qName := *(pluginsState.qName)
	whitelist, reason, _ := plugin.patternMatcher.Eval(&qName)

	if whitelist {
		pluginsState.sessionData["whitelisted"] = true
		if plugin.logger != nil {
			var clientIPStr string
			if *(pluginsState.clientProto) == "udp" {
				clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
			} else {
				clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
			}
			var line string
			if plugin.format == "tsv" {
				now := time.Now()
				year, month, day := now.Date()
				hour, minute, second := now.Clock()
				tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
				line = fmt.Sprintf("%s\t%s\t%s\t%s\n", tsStr, clientIPStr, StringQuote(qName), StringQuote(reason))
			} else if plugin.format == "ltsv" {
				line = fmt.Sprintf("time:%d\thost:%s\tqname:%s\tmessage:%s\n", time.Now().Unix(), clientIPStr, StringQuote(qName), StringQuote(reason))
			} else {
				dlog.Fatalf("unexpected log format: [%s]", plugin.format)
			}
			if plugin.logger == nil {
				return errors.New("Log file not initialized")
			}
			_, _ = plugin.logger.Write([]byte(line))
		}
	}
	return nil
}
