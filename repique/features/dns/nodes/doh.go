package nodes

import (
	"context"
	//"net"
	"net/http"

	//"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/protocols/tls"
)

type dohnode struct {
	*tlsnode
	trans           *http.Transport
	path            *string
	method          tls.HttpMethod
}

func (_ *dohnode) proto() string {
	return DoH
}

func (n *dohnode) exchange(blob *[]byte, args ...interface{}) (*[]byte, error) {
	var ctx context.Context
	if len(args) > 0 {
		if args[0] != nil {
			ctx = args[0].(context.Context)
		}
	}
	var cbs []interface{}
	if len(args) > 1 {
		cbs = append(cbs, args[1])
	}
	return n.FetchHTTPS(n.trans, nil, n.path, n.method, true, ctx, blob, 0, cbs...)
}

// bootstrap
type doh_bs_node struct {
	*dohnode
	*tls_bs_ips
}

func (n *doh_bs_node) material() marshaling { 
	return n.tls_bs_ips
}
