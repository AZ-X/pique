// +build !windows

package main

import (
	"net"
	"time"

	"github.com/jedisct1/dlog"
)

func NetProbe(address string, ifi *string, timeout int) error {
	if len(address) <= 0 || timeout == 0 {
		return nil
	}
	var err error
	endpoint, err := ResolveEndpoint(address)
	if err != nil {
		return err
	}
	retried := false
	if timeout < 0 {
		timeout = MaxTimeout
	} else {
		timeout = Min(MaxTimeout, timeout)
	}
	var localAddr net.Addr
	if ifi != nil {
		for tries := timeout; tries > 0; tries-- {
			if localAddr, err = GetInferfaceDefaultAddr(*ifi, "udp"); err != nil {
				dlog.Debug(err)
				time.Sleep(1 * time.Second)
			} else {
				break
			}
		}
	}
	d := &net.Dialer{LocalAddr:localAddr, KeepAlive:-1, FallbackDelay:-1,}
	for tries := timeout; tries > 0; tries-- {
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
