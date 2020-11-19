// This source code refers to The Go Authors for copyright purposes.
// The master list of authors is in the main Go distribution,
// visible at https://tip.golang.org/AUTHORS.

package unclassified

import (
	_ "unsafe"
)

//go:linkname Curve25519_Basepoint vendor/golang.org/x/crypto/curve25519.Basepoint
var Curve25519_Basepoint []byte

//go:linkname Curve25519_X25519 vendor/golang.org/x/crypto/curve25519.X25519
func Curve25519_X25519(scalar, point []byte) ([]byte, error)

//go:linkname Chacha20_HChaCha20 vendor/golang.org/x/crypto/chacha20.HChaCha20
func Chacha20_HChaCha20(key, nonce []byte) ([]byte, error)