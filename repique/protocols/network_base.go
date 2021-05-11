package protocols

import (
	"time"

	"github.com/AZ-X/pique/repique/conceptions"
)

type NetworkBase struct {
	Proxies    *conceptions.NestedProxy  // individual proxies chain
	IFI        *string                   // LocalInterface Info; multi-gateway
	Network    string                    // mutable; can be individual network
	Alive      time.Duration             // keep alive; communication protocol
	Timeout    time.Duration             // communication protocol
}