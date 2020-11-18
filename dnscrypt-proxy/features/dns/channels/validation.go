package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
	_ "unsafe"

	"github.com/miekg/dns"

	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
)

var (
	Error_Packet_Size1   = &Error{Ex:"validation: invalid packet size of query"}
	Error_Packet_Size2   = &Error{Ex:"validation: invalid packet size of answer"}
	Error_DNS_Header1    = &Error{Ex:"validation: invalid dns header of query"}
	Error_DNS_Header2    = &Error{Ex:"validation: invalid dns header of answer"}
	Error_DNS_QName      = &Error{Ex:"validation: invalid dns qname of query"}
	Error_DNS_Qualified  = &Error{Ex:"validation: qname is not fully qualified"}
	Error_DNS_OPT        = &Error{Ex:"validation: OPT record is more than one"}
	Error_DNS_NO_IPv6    = &Error{Ex:"validation: disable IPv6 by default"}
)


type Validation struct {
	*Config
	f FChannelByName
}

func (_ *Validation) Name() string {
	return Channel_Validation
}

func (v *Validation) Init(cfg *Config, f FChannelByName) {
	v.Config = cfg
	v.f = f
}

//go:linkname unpack github.com/miekg/dns.(*Msg).unpack
func unpack(dns *dns.Msg, dh dns.Header, msg []byte, off int) (err error)

//go:linkname unpackMsgHdr github.com/miekg/dns.unpackMsgHdr
func unpackMsgHdr(msg []byte, off int) (dns.Header, int, error)

//go:linkname setHdr github.com/miekg/dns.(*Msg).setHdr
func setHdr(dns *dns.Msg, dh dns.Header)

const _QR = 1 << 15
const rr_throttle = 15 // quote miekg/dns 'as they are attacker controlled'; thus can be partially treated 
func msgAcceptFunc(dh dns.Header) bool {
	isResponse := dh.Bits&_QR != 0

	// Don't allow dynamic updates, because then the sections can contain a whole bunch of RRs.
	opcode := int(dh.Bits>>11) & 0xF
	switch opcode {
	case dns.OpcodeQuery, dns.OpcodeNotify, dns.OpcodeIQuery, dns.OpcodeStatus:
	default: return false
	}

	if dh.Qdcount != 1 {
		return false
	}
	
	if !isResponse && dh.Ancount != 0 {
		return false
	}
	// IXFR request could have one SOA RR in the NS section. See RFC 1995, section 3.
	if (!isResponse && dh.Nscount > 1) || (isResponse && dh.Nscount > rr_throttle) {
		return false
	}
	// Extra
	if (!isResponse && dh.Arcount > 2) || (isResponse && dh.Arcount > rr_throttle) {
		return false
	}
	return true
}

func (v *Validation) Handle(s *Session) Channel {
	if s.LastState == STAR {
		goto V1_Unpack
	}
	if s.LastState == CP1_OK {
		goto V2_Pack
	}
	if s.LastState == R_OK {
		goto V3_Unpack
	}
	if s.LastState == A23_OK {
		goto V34_Pack
	}
	panic(Session_State_Error)
StateN:
	s.State |= s.LastState
	return v.f(StateNChannel[s.LastState])
V1_NOK:
	s.LastState = V1_NOK
	goto StateN
V1_Unpack:{
	in_bytes := *s.RawIn
	if len(in_bytes) < common.MinDNSPacketSize || len(in_bytes) > common.MaxDNSUDPPacketSize {
		s.LastError = Error_Packet_Size1
		goto V1_NOK
	}
	var dh dns.Header
	var off int
	var err error
	dh, off, err = unpackMsgHdr(in_bytes, 0)
	s.ID = dh.Id
	if err != nil {
		s.LastError = err
		goto V1_NOK
	}
	if !msgAcceptFunc(dh) {
		common.Program_dbg_full_log("IN1 dns header => %v", dh)
		s.LastError = Error_DNS_Header1
		goto V1_NOK
	}
	msg := &dns.Msg{}
	setHdr(msg, dh)
	if err = unpack(msg, dh, in_bytes, off); err != nil {
		s.LastError = err
		goto V1_NOK
	}
	question := msg.Question[0]
	if _, ok := dns.IsDomainName(question.Name); !ok {
		s.LastError = Error_DNS_QName
		goto V1_NOK
	}
	if question.Qclass == dns.ClassINET && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) && !dns.IsFqdn(question.Name) {
		s.LastError = Error_DNS_Qualified
		goto V1_NOK
	}
	s.Question = &question
	s.Request = msg
	if v.BlockIPv6 == nil || *v.BlockIPv6 && (question.Qclass == dns.ClassINET && question.Qtype == dns.TypeAAAA) {
		s.LastError = Error_DNS_NO_IPv6
		goto V1_NOK
	}
	opt_counter := 0
	// rfc6891: If a query message with more than one OPT RR is received, a FORMERR (RCODE=1) MUST be returned
	for i := len(msg.Extra) - 1; i >= 0; i-- {
		if msg.Extra[i].Header().Rrtype == dns.TypeOPT {
			s.OPTOrigin = msg.Extra[i].(*dns.OPT)
			opt_counter++
			if opt_counter > 1 {
				s.LastError = Error_DNS_OPT
				goto V1_NOK
			}
		}
	}
	s.LastState = V1_OK
	goto StateN
		}
V2_Pack:{
	if bytes, err := s.Request.Pack(); err != nil {
		s.LastError = err 
		s.LastState = V2_NOK
	} else {
		s.RawOut = &bytes
		s.LastState = V2_OK
	}
	goto StateN
		}
V3_NOK:
	s.LastState = V3_NOK
	s.RawIn = nil
	goto StateN
V3_Unpack:{
	s.RawOut = nil
	in_bytes := *s.RawIn
	if len(in_bytes) < common.MinDNSPacketSize || len(in_bytes) > common.MaxDNSPacketSize {
		s.LastError = Error_Packet_Size2
		goto V1_NOK
	}
	var dh dns.Header
	var off int
	var err error
	dh, off, err = unpackMsgHdr(in_bytes, 0)
	if err != nil {
		s.LastError = err
		goto V3_NOK
	}
	if !msgAcceptFunc(dh) {
		common.Program_dbg_full_log("IN2 dns header => %v", dh)
		s.LastError = Error_DNS_Header2
		goto V3_NOK
	}
	msg := &dns.Msg{}
	if err = unpack(msg, dh, in_bytes, off); err != nil {
		s.LastError = err
		goto V3_NOK
	}
	s.Response = msg
	s.LastState = V3_OK
	goto StateN
		}
V34_Pack:{
	if bytes, err := s.Response.Pack(); s.State&V4_NOK != V4_NOK && err != nil {
		s.LastError = err 
		s.RawIn = nil
		s.LastState = V4_NOK
	} else {
		s.RawOut = &bytes
		s.LastState = V45_OK
	}
	goto StateN
		}
}
