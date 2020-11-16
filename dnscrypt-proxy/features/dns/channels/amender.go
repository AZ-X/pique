package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
	"strings"
	_ "unsafe"

	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

const (
	Zero_DNS_Msg_ID = true
)


type Amender struct {
	*Config
	f FChannelByName
	qm *dns.TXT
}

func (a *Amender) Name() string {
	return Channel_Amender
}

func (a *Amender) Init(cfg *Config, f FChannelByName) {
	a.Config = cfg
	a.f = f
	if len(a.QueryMeta) != 0 {
		a.qm = new(dns.TXT)
		a.qm.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeTXT,
		Class: dns.ClassINET, Ttl: 86400}
		a.qm.Txt = cfg.QueryMeta
	}
	if cfg.NodataTTL == nil {
		ttl := DefaultTTL
		cfg.NodataTTL = &ttl
	}
}

//go:linkname popEdns0 github.com/miekg/dns.(*Msg).popEdns0
func popEdns0(dns *dns.Msg) *dns.OPT


func (a *Amender) Handle(s *Session) Channel {
	if s.LastState == V1_OK {
		goto A1
	}
	switch s.LastState {
	case V1_NOK, V2_NOK, V3_NOK, V4_NOK, CP1_NOK, CP2_OK,CP2_NOK, R_NOK, RCP_NOK:
		goto A23
	}
	panic(Session_State_Error)
StateN:
	s.State |= s.LastState
	return a.f(StateNChannel[s.LastState])
A1:{
	/*
	in general following rfc7626 <DNS Privacy Considerations>
	rfc6973 Data Minimization :
	Identifiers/Data/Observers/Fingerprinting/Persistence of identifiers/Correlation/Retention
	*/
	//Id
	if Zero_DNS_Msg_ID {
		s.Request.Id = 0
	} else {
		s.Request.Id = dns.Id()
	}
	//Extra
	if a.qm != nil {
		s.Request.Extra = append(s.Request.Extra, a.qm)
	}
	//EDNS
	//rfc8484:
	//MAY have one or more Extension Mechanisms for DNS
	//DoH servers using this media type MUST ignore the value given for the EDNS UDP payload size in DNS requests.
	if s.OPTOrigin != nil {
		popEdns0(s.Request)
	}
	s.Request.SetEdns0(common.MaxDNSUDPPacketSize, true)
	s.LastState = A1_OK
	goto StateN
	}
A23:{
	if s.Request == nil {
		s.Request = &dns.Msg{}
	}
	switch s.LastState {
		case CP1_NOK, RCP_NOK, CP2_OK, CP2_NOK:
		default:s.Response = &dns.Msg{}
		switch s.LastError {
			case Error_Packet_Size1,
				 Error_Packet_Size2,
				 Error_DNS_Header1,
				 Error_DNS_Header2,
				 Error_DNS_QName,
				 Error_DNS_Qualified,
				 Error_DNS_OPT: s.Response.SetRcodeFormatError(s.Request)
			case Error_Stub_Internal,
				 Error_Stub_SvrFault,
				 Error_Stub_Timeout: s.Response.SetRcode(s.Request, dns.RcodeServerFailure)
			case Error_DNS_NO_IPv6:
					s.Response.SetRcode(s.Request, dns.RcodeSuccess)
					soa := new(dns.SOA)
					soa.Ns = "a.root-servers.net."
					parentZone := strings.SplitN(s.Name, Dot, 2)[1]
					if len(parentZone) == 0 {
						parentZone = Dot
					}
					soa.Hdr = dns.RR_Header{Name:parentZone, Rrtype:dns.TypeSOA, Class:dns.ClassINET, Ttl: *a.Config.NodataTTL,}
					s.Response.Ns = []dns.RR{soa}
			default:
				switch a.Config.BlockedQueryResponse {
					case "nxdomain": s.Response.SetRcode(s.Request, dns.RcodeNameError)
					default:         s.Response.SetRcode(s.Request, dns.RcodeRefused)
				}
		}
	}
	s.Response.Id = s.ID
	popEdns0(s.Response)
	if s.OPTOrigin != nil {
		s.Response.Extra = append(s.Response.Extra, s.OPTOrigin)
	}
	if s.IsUDPClient {
		udpSize := common.MaxDNSUDPPacketSize
		if s.OPTOrigin != nil {
			udpSize = int(s.OPTOrigin.UDPSize())
		}
		if s.Response.Len() > udpSize {
			s.Response.Truncate(udpSize)
			if s.Response.Truncated {
				dlog.Debugf("response has been truncated, qName: %s, sName: %s", s.Name, *s.ServerName)
				s.Response.Rcode = dns.RcodeServerFailure //prevent Cache, no redirection to tcp from udp
			}
		}
	}
	s.LastState = A23_OK
	goto StateN
	}
}
