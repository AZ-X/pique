package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
	"fmt"
	"strings"
	"time"

	"github.com/AZ-X/pique/repique/common"

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
		switch s.LastError {
		case Error_DNS_NO_IPv6, Error_Stub_Timeout, Error_Stub_SvrFault, Error_Stub_Internal: 
				dlog.Debug(s.LastError)
		default:
				if _, ok := s.LastError.(*Error_CP_Reason); ok {
					dlog.Debug(s.LastError)
				} else {
					dlog.Warn(s.LastError)
				}
		}
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
	for i := len(s.Response.Answer); i > 0; i-- {
		rr := s.Response.Answer[i-1]
		switch rr.Header().Rrtype {
		case dns.TypeA:
			answer = rr.(*dns.A).A.String() + " v4"
			break
		case dns.TypeAAAA:
			answer = rr.(*dns.AAAA).AAAA.String()  + " v6"
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
		if s.Response.Truncated {
			answer += " **Truncated**"
		}
		if s.Response.Rcode != dns.RcodeSuccess {
			answer = fmt.Sprintf("%s %s", answer, dns.RcodeToString[s.Response.Rcode])
		}
		if s.State&CP1_NOK == CP1_NOK || s.State&CP2_NOK == CP2_NOK || s.Question == nil || *s.Question != s.Request.Question[0] {
			answer = fmt.Sprintf("%s(R)", answer)
		}
		if len(s.Response.Ns) > 0 {
			answer = fmt.Sprintf("%s Ns%d", answer, len(s.Response.Ns))
		}
		if len(s.Response.Extra) > 0 {
			answer = fmt.Sprintf("%s Ex%d", answer, len(s.Response.Extra))
		}
		if s.ExtraServerName != nil {
			dlog.Debugf("ID: %5d O: |%-25s| [%s%s]", s.ID, answer, *s.ServerName, *s.ExtraServerName)
		} else {
			dlog.Debugf("ID: %5d O: |%-25s| [%s]", s.ID, answer, *s.ServerName)
		}
	}
	s.LastState = L_OK
	s.State |= s.LastState
	return l.f(StateNChannel[s.LastState])
}
