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
