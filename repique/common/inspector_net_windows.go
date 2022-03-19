package common

import (
	"crypto/tls"
	"io"
	"net"
	"syscall"
	"os"

	"github.com/jedisct1/dlog"
)

func temporary(err error) bool {
	if err == io.EOF {
		return true
	}
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

type inspectForciblyConnTLS struct {
	*tls.Conn
}

func (c *inspectForciblyConnTLS) Read(b []byte) (n int, err error) {
	return retryOnRW(c.Conn.Read, b)
}

func (c *inspectForciblyConnTLS) Write(b []byte) (n int, err error) {
	return retryOnRW(c.Conn.Write, b)
}

type inspectForciblyConnTCP struct {
	net.Conn
}

func (c *inspectForciblyConnTCP) Read(b []byte) (n int, err error) {
	return retryOnRW(c.Conn.Read, b)
}

func (c *inspectForciblyConnTCP) Write(b []byte) (n int, err error) {
	return retryOnRW(c.Conn.Write, b)
}

type inspectForciblyConnUDP struct {
	net.PacketConn
}

func (c *inspectForciblyConnUDP) Read(b []byte) (n int, err error) {
	return retryOnRW(c.PacketConn.(net.Conn).Read, b)
}

func (c *inspectForciblyConnUDP) Write(b []byte) (n int, err error) {
	return retryOnRW(c.PacketConn.(net.Conn).Write, b)
}

func (c *inspectForciblyConnUDP) RemoteAddr() net.Addr {
	return c.PacketConn.(net.Conn).RemoteAddr()
}

func getInspector(conn net.Conn) net.Conn {
	switch t := conn.(type) {
		case net.PacketConn: return &inspectForciblyConnUDP{PacketConn:t,}
		case *net.TCPConn: return &inspectForciblyConnTCP{Conn:t,}
		case *tls.Conn: return &inspectForciblyConnTLS{Conn:t,}
		default: return conn
	}
}
