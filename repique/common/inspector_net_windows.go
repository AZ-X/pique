package common

import (
	"net"
	"syscall"
	"time"
	"os"

	"github.com/jedisct1/dlog"
)

func temporary(err error) bool {
	if oe, ok := err.(*net.OpError); ok {
		if syserr, ok := oe.Err.(*os.SyscallError); ok && syserr.Syscall == "wsarecv" {
			if errno, ok := syserr.Err.(syscall.Errno); ok {
				switch errno {
					case 10052, 10053, 10054: return true // WSAENETRESET, WSAECONNABORTED, WSAECONNRESET
				}
			}
		}
	}
	return false
}

type inspectForciblyConn struct {
	raw net.Conn
}

func (c *inspectForciblyConn) LocalAddr() net.Addr {
	return c.raw.LocalAddr()
}

func (c *inspectForciblyConn) RemoteAddr() net.Addr {
	return c.raw.RemoteAddr()
}

func (c *inspectForciblyConn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

func (c *inspectForciblyConn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

func (c *inspectForciblyConn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

func (c *inspectForciblyConn) Close() error {
	return c.raw.Close()
}

func retryOnRW(f func([]byte) (n int, err error), b []byte) (n int, err error) {
	fCounter := 0
Retry:
	if n, err = f(b); err != nil && temporary(err) {
		if fCounter < retry_on_forcibly {
			if fCounter == 0 {
				dlog.Debug("retry on forcible block")
			}
			fCounter++
			goto Retry
		} else {
			dlog.Warn("forcible block is willfully activated, see next debug log for last error")
		}
	}
	return
}

func (c *inspectForciblyConn) Read(b []byte) (n int, err error) {
	return retryOnRW(c.raw.Read, b)
}

func (c *inspectForciblyConn) Write(b []byte) (n int, err error) {
	return retryOnRW(c.raw.Write, b)
}

func getInspector(conn net.Conn) net.Conn {
	return &inspectForciblyConn{raw:conn}
}
