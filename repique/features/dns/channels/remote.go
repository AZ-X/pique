package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
	"sync"
)

var (
	Error_Stub_Internal = &Error{Ex:"remote: can not serve query due to internal fault"}
	Error_Stub_SvrFault = &Error{Ex:"remote: stub server fault"}
	Error_Stub_Timeout  = &Error{Ex:"remote: timeout"}
)

type Remote struct {
	f FChannelByName
	cache_enabled bool
}

func (r *Remote) Name() string {
	return Channel_Remote
}

func (r *Remote) Init(cfg *Config, f FChannelByName) {
	r.f = f
	r.cache_enabled = cfg.CacheSize != nil
}

func (r *Remote) Handle(s *Session) Channel {
	r.f(Channel_Stub).Handle(s)
	if r.cache_enabled && s.LastState != R_OK {
		if s.rep_job == nil {
			s.rep_job = &sync.Once{}
		}
		s.rep_job.Do(func () {
			var dup Session = *s
			dup.LastState = A1_OK
			go repeatRequest(r.f(Channel_CP), &dup)
		})
	}
	return r.f(StateNChannel[s.LastState])
}

const cache_insurance = 10
var svrName = NonSvrName
func repeatRequest(r Channel, s *Session) {
	state := s.LastState
	for i:=0; i < cache_insurance; i++ {
		if i >= cache_insurance/2 {
			s.ServerName = &svrName
			s.ExtraServerName = nil
		}
		s.LastState = state
		Handle(r, s)
		if s.State&R_OK == R_OK || s.State&CP1_NOK == CP1_NOK {
			break
		}
	}
}


