package common

import (
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