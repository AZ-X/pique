package dns

import (
	"strings"

	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
	"github.com/miekg/dns"
)

type PluginBlockUnqualified struct {
}

func (plugin *PluginBlockUnqualified) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginBlockUnqualified) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	if strings.IndexByte(*(pluginsState.qName), '.') >= 0 {
		return nil
	}
	synth := common.EmptyResponseFromMessage(msg)
	synth.Rcode = dns.RcodeNameError
	pluginsState.synthResponse = synth
	pluginsState.state = PluginsStateSynth
	pluginsState.returnCode = PluginsReturnCodeSynth

	return nil
}
