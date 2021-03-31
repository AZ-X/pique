package common

import (
	"net"
)

func getInspector(conn net.Conn) net.Conn {
	return conn
}

func temporary(err error) bool { return false }