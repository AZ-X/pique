package channels



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
)

var (
	Error_Stub_Internal = &Error{Ex:"remote: can not serve query due to internal fault"}
	Error_Stub_SvrFault = &Error{Ex:"remote: stub server fault"}
	Error_Stub_Timeout  = &Error{Ex:"remote: timeout"}
)


//type Remote struct {
//	f channels.FChannelByName
//	handler func(*channels.Session) error
//}
//
//func (r *Remote) Name() string {
//	return channels.Channel_Remote
//}
//
//func (a *Remote) Init(cfg *channels.Config, f channels.FChannelByName) {
//	a.f = f
//}
//
//func (a *Remote) Handle(s *channels.Session) channels.Channel {
//	if err := a.handler(s); err == nil {
//		s.LastState = channels.R_OK
//	} else {
//		s.LastError = err
//		if s.Response != nil {
//			s.LastState = channels.RCP_NOK
//		} else {
//			s.LastState = channels.R_NOK
//		}
//	}
//	return a.f(channels.StateNChannel[s.LastState])
//}