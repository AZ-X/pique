package main

import (
	"context"
	"io"
	"net"
	_ "unsafe"
)


const (
	socksAuthMethodNotRequired         socksAuthMethod = 0x00 // no authentication required
	socksAuthMethodUsernamePassword    socksAuthMethod = 0x02 // use username/password
)

// A Command represents a SOCKS command.
type socksCommand int
// An AuthMethod represents a SOCKS authentication method.
type socksAuthMethod int

// A Dialer holds SOCKS-specific options.
type socksDialer struct {
	cmd          socksCommand // either CmdConnect or cmdBind
	proxyNetwork string       // network between a proxy server and a client
	proxyAddress string       // proxy server address

	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)

	// AuthMethods specifies the list of request authentication
	// methods.
	// If empty, SOCKS client requests only AuthMethodNotRequired.
	AuthMethods []socksAuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate func(context.Context, io.ReadWriter, socksAuthMethod) error
}

type socksUsernamePassword struct {
	Username string
	Password string
}

//go:linkname connect http.connect
func (d *socksDialer) connect(ctx context.Context, c net.Conn, address string) (_ net.Addr, ctxErr error)

//go:linkname Authenticate http.Authenticate
func (up *socksUsernamePassword) Authenticate(ctx context.Context, rw io.ReadWriter, auth socksAuthMethod) error



