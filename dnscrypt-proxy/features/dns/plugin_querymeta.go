package dns

import (
	"github.com/miekg/dns"
)

type PluginQueryMeta struct {
	QueryMetaRR *dns.TXT
}

func (plugin *PluginQueryMeta) Init(proxy *Proxy) error {
	QueryMetaRR := new(dns.TXT)
	QueryMetaRR.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeTXT,
		Class: dns.ClassINET, Ttl: 86400}
	QueryMetaRR.Txt = proxy.QueryMeta
	plugin.QueryMetaRR = QueryMetaRR
	return nil
}

func (plugin *PluginQueryMeta) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	msg.Extra = []dns.RR{plugin.QueryMetaRR}
	return nil
}
