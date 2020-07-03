package main

import (
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

func SetDNSSECFlag(msg *dns.Msg) {
	if len(msg.Question) > 0 {
		msg.Question[0].Qtype = dns.TypeOPT
	}
	msg.CheckingDisabled = true
	msg.SetEdns0(4096, true)
	opt := msg.IsEdns0()
	//https://www.iana.org/assignments/dns-sec-alg-numbers
	//8	RSA/SHA-256	RSASHA256
	//15 Ed25519	ED25519
	
	dau := new(dns.EDNS0_DAU)
	dau.AlgCode = append(append(dau.AlgCode, dns.RSASHA256), dns.ED25519)
	opt.Option = append(opt.Option, dau)
	
	dhu := new(dns.EDNS0_DHU)
	dhu.AlgCode = append(dhu.AlgCode, dns.SHA256)
	opt.Option = append(opt.Option, dhu)
	
	n3u := new(dns.EDNS0_N3U)
	n3u.AlgCode = append(n3u.AlgCode, dns.SHA256)
	opt.Option = append(opt.Option, n3u)

	ext := new(dns.EDNS0_PADDING)
	ext.Padding = make([]byte, 32)
	for i,_ := range ext.Padding {
		ext.Padding[i] = 0xff
	}
	opt.Option = append(opt.Option, ext)
}

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
	dstMsg := &dns.Msg{MsgHdr: srcMsg.MsgHdr, Compress: true}
	dstMsg.Question = srcMsg.Question
	dstMsg.Response = true
	if srcMsg.RecursionDesired {
		dstMsg.RecursionAvailable = true
	}
	dstMsg.RecursionDesired = false
	dstMsg.CheckingDisabled = false
	dstMsg.AuthenticatedData = false
	if edns0 := srcMsg.IsEdns0(); edns0 != nil {
		dstMsg.SetEdns0(edns0.UDPSize(), edns0.Do())
	}
	return dstMsg
}

func TruncatedResponse(srcMsg *dns.Msg) {
	srcMsg = EmptyResponseFromMessage(srcMsg)
	srcMsg.Truncated = true
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, blockedQueryResponse string, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
	dstMsg := EmptyResponseFromMessage(srcMsg)
	switch blockedQueryResponse {
		case "nxdomain":
			dstMsg.Rcode = dns.RcodeNameError
		case "refused":
			dstMsg.Rcode = dns.RcodeRefused
		default:
			dstMsg.Rcode = dns.RcodeSuccess
			questions := srcMsg.Question
			if len(questions) == 0 {
				return dstMsg
			}
			question := questions[0]
			sendHInfoResponse := true
	
			if ipv4 != nil && question.Qtype == dns.TypeA {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
				rr.A = ipv4.To4()
				if rr.A != nil {
					dstMsg.Answer = []dns.RR{rr}
					sendHInfoResponse = false
				}
			} else if ipv6 != nil && question.Qtype == dns.TypeAAAA {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
				rr.AAAA = ipv6.To16()
				if rr.AAAA != nil {
					dstMsg.Answer = []dns.RR{rr}
					sendHInfoResponse = false
				}
			}
	
			if sendHInfoResponse {
				hinfo := new(dns.HINFO)
				hinfo.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeHINFO,
					Class: dns.ClassINET, Ttl: 1}
				hinfo.Cpu = ""
				hinfo.Os = ""
				dstMsg.Answer = []dns.RR{hinfo}
			}
	}
	return dstMsg
}

func NormalizeQName(str string) (string, error) {
	if _,ok := dns.IsDomainName(str); ok {
		return dns.CanonicalName(str), nil
	}
	return "", errors.New("Invalid QName")
}

func getMinTTL(msg *dns.Msg, minTTL uint32, maxTTL uint32, cacheNegMinTTL uint32, cacheNegMaxTTL uint32) time.Duration {
	if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) || (len(msg.Answer) <= 0 && len(msg.Ns) <= 0) {
		return time.Duration(cacheNegMinTTL) * time.Second
	}
	var ttl uint32
	if msg.Rcode == dns.RcodeSuccess {
		ttl = uint32(maxTTL)
	} else {
		ttl = uint32(cacheNegMaxTTL)
	}
	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		for _, rr := range msg.Ns {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	if msg.Rcode == dns.RcodeSuccess {
		if ttl < minTTL {
			ttl = minTTL
		}
	} else {
		if ttl < cacheNegMinTTL {
			ttl = cacheNegMinTTL
		}
	}
	return time.Duration(ttl) * time.Second
}

func setMaxTTL(msg *dns.Msg, ttl uint32) {
	for _, rr := range msg.Answer {
		if ttl < rr.Header().Ttl {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range msg.Ns {
		if ttl < rr.Header().Ttl {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range msg.Extra {
		header := rr.Header()
		if header.Rrtype == dns.TypeOPT {
			continue
		}
		if ttl < rr.Header().Ttl {
			rr.Header().Ttl = ttl
		}
	}
}

func updateTTL(msg *dns.Msg, expiration time.Time) {
	until := time.Until(expiration)
	ttl := uint32(0)
	if until > 0 {
		ttl = uint32(until / time.Second)
	}
	for _, rr := range msg.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
}

func hasEDNS0Padding(packet []byte) (bool, error) {
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return false, err
	}
	if edns0 := msg.IsEdns0(); edns0 != nil {
		for _, option := range edns0.Option {
			if option.Option() == dns.EDNS0PADDING {
				return true, nil
			}
		}
	}
	return false, nil
}

func removeEDNS0Options(msg *dns.Msg) bool {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		return false
	}
	edns0.Option = []dns.EDNS0{}
	return true
}
