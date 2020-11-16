package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
	"fmt"
	"strings"
	"time"

	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)


type Logger struct {
	*Config
	f FChannelByName
	logger        *lumberjack.Logger
}

func (l *Logger) Name() string {
	return Channel_Logger
}

func (l *Logger) Init(cfg *Config, f FChannelByName) {
	l.Config = cfg
	l.f = f
	if cfg.QueryLog != nil && cfg.QueryLog.File != nil {
		l.logger = &lumberjack.Logger{LocalTime:true, Filename:*cfg.QueryLog.File,}
		if cfg.QueryLog.Format == nil {
			format := "tsv"
			cfg.QueryLog.Format = &format
		}
		switch *cfg.QueryLog.Format {
		case "tsv", "ltsv":
		default: panic("unsupported query format")
		}
	}
}

func (l *Logger) Handle(s *Session) Channel {
	if s.LastError != nil {
		dlog.Debug(s.LastError)
	} else {
		if l.logger != nil {
			qType, ok := dns.TypeToString[s.Qtype]
			if !ok {
				qType = string(qType)
			}
			for _, ignored := range l.QueryLog.IgnoredQtypes {
				if strings.EqualFold(ignored, qType) {
					goto ConsoleLog
				}
			}
			returnCode := dns.RcodeToString[s.Response.Rcode]
			var line string
			switch *l.QueryLog.Format {
			case "tsv":	now := time.Now()
						year, month, day := now.Date()
						hour, minute, second := now.Clock()
						tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
						line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", tsStr, common.StringQuote(&s.Name), qType, returnCode, common.StringQuote(s.ServerName))
			case "ltsv":line = fmt.Sprintf("time:%d\tmessage:%s\ttype:%s\treturn:%s\tserver:%s\n",
						time.Now().Unix(), common.StringQuote(&s.Name), qType, returnCode, common.StringQuote(s.ServerName))
			}
			l.logger.Write([]byte(line))
		}
	}
ConsoleLog:
	answer := EMPTY
	for _, rr := range s.Response.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeA:
			answer = rr.(*dns.A).A.String()
			break
		case dns.TypeAAAA:
			answer = rr.(*dns.AAAA).AAAA.String()
			break
		}
	}
	if *s.ServerName == NonSvrName {
		question := EMPTY
		if len(s.Request.Question) > 0 {
			question = s.Name
		}
		dlog.Debugf("ID: %5d I: |%-15s| O: |%-15s| Code:%s", s.ID, question, answer, dns.RcodeToString[s.Response.Rcode])
	} else {
		if answer == EMPTY {
			if s.Response.Truncated {
				answer += " **Truncated**"
			} else {
				answer += " " + dns.RcodeToString[s.Response.Rcode]
			}
		}
		dlog.Debugf("ID: %5d O: |%-15s| [%s]", s.ID, answer, *s.ServerName)
	}

	s.LastState = L_OK
	s.State |= s.LastState
	return l.f(StateNChannel[s.LastState])
}
