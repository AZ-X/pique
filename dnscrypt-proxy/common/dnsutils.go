package common

import (
	"errors"

	"github.com/miekg/dns"
)

func SetDNSSECFlag(msg *dns.Msg) {
	if len(msg.Question) > 0 {
		msg.Question[0].Qtype = dns.TypeMX
	}
	msg.CheckingDisabled = true
	msg.SetEdns0(MaxDNSUDPPacketSize-64, true)
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
		ext.Padding[i] = 0x00
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

func RefusedResponseFromMessage(srcMsg *dns.Msg, BlockedQueryResponse string) *dns.Msg {
	dstMsg := EmptyResponseFromMessage(srcMsg)
	switch BlockedQueryResponse {
		case "nxdomain":
			dstMsg.Rcode = dns.RcodeNameError
		case "refused":
			dstMsg.Rcode = dns.RcodeRefused
	}
	return dstMsg
}

func NormalizeQName(str string) (string, error) {
	if _,ok := dns.IsDomainName(str); ok {
		return dns.CanonicalName(str), nil
	}
	return "", errors.New("Invalid QName")
}
