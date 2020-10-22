// +build !windows

package behaviors

import (
	"net"
	"time"

	"github.com/jedisct1/dlog"
)

func NetProbe(address string, ifi *string, Timeout int) error {
	if len(address) <= 0 || Timeout == 0 {
		return nil
	}
	var err error
	endpoint, err := ResolveEndpoint(address)
	if err != nil {
		return err
	}
	retried := false
	if Timeout < 0 {
		Timeout = MaxTimeout
	} else {
		Timeout = Min(MaxTimeout, Timeout)
	}
	var localAddr net.Addr
	if ifi != nil {
		for tries := Timeout; tries > 0; tries-- {
			if localAddr, err = GetInferfaceDefaultAddr(*ifi, "udp"); err != nil {
				dlog.Debug(err)
				time.Sleep(1 * time.Second)
			} else {
				break
			}
		}
	}
	d := &net.Dialer{LocalAddr:localAddr, KeepAlive:-1, FallbackDelay:-1,}
	for tries := Timeout; tries > 0; tries-- {
		pc, err := d.Dial("udp", endpoint.String())
		if err != nil {
			if !retried {
				retried = true
				dlog.Notice("network not available yet -- waiting...")
			}
			dlog.Debug(err)
			time.Sleep(1 * time.Second)
			continue
		}
		pc.Close()
		dlog.Notice("network connectivity detected")
		return nil
	}
	dlog.Error("Timeout while waiting for network connectivity")
	return nil
}
