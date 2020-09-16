package xsecretbox

import (
	"errors"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
)

// SharedKey computes a shared secret compatible with the one used by `crypto_box_xchacha20poly1305``
func SharedKey(secretKey [32]byte, publicKey [32]byte) (*[32]byte, error) {
	var sharedKey *[32]byte = new([32]byte)
	x, err := curve25519.X25519(secretKey[:], publicKey[:])
	copy(sharedKey[:], x)
	if (err != nil) {
		return sharedKey, err
	}
	c := byte(0)
	for i := 0; i < 32; i++ {
		c |= sharedKey[i]
	}
	if c == 0 {
		return sharedKey, errors.New("weak public key")
	}
	var zeros [16]byte
	result, err := chacha20.HChaCha20(sharedKey[:], zeros[:])
	if (err != nil) {
		return sharedKey, err
	}
	copy(sharedKey[:], result)
	return sharedKey, nil
}
