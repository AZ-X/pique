// This source code refers to The Go Authors for copyright purposes.
// The master list of authors is in the main Go distribution,
// visible at https://tip.golang.org/AUTHORS.

package unclassified

import (
	_ "unsafe"
)

var Curve25519_Basepoint []byte

var basePoint = [32]byte{9}

func init() { Curve25519_Basepoint = basePoint[:] }

type err string
func (_ *err) Error() string { return "crypto/ecdh: bad X25519 remote ECDH input: low order point"}

func Curve25519_X25519(scalar, point []byte) ([]byte, error) {
	dst := make([]byte, 32)
	x25519ScalarMult(dst, scalar, point)
	if isZero(dst) {
		return nil, new(err)
	}
	return dst, nil
}

//go:linkname isZero crypto/ecdh.isZero
func isZero(a []byte) bool

//go:linkname x25519ScalarMult crypto/ecdh.x25519ScalarMult
func x25519ScalarMult(dst, scalar, point []byte)

//go:linkname Chacha20_HChaCha20 vendor/golang.org/x/crypto/chacha20.HChaCha20
func Chacha20_HChaCha20(key, nonce []byte) ([]byte, error)