// This source code refers to The Go Authors for copyright purposes.
// The master list of authors is in the main Go distribution,
// visible at https://tip.golang.org/AUTHORS.

package unclassified

import (
	_ "unsafe"
)

// Cipher is a stateful instance of ChaCha20 or XChaCha20 using a particular key
// and nonce. A *Cipher implements the cipher.Stream interface.

//go:linkname Cipher vendor/golang.org/x/crypto/chacha20.Cipher
type Cipher struct {}

//go:linkname (*Cipher).SetCounter vendor/golang.org/x/crypto/chacha20.(*Cipher).SetCounter
func (s *Cipher) SetCounter(counter uint32)

//go:linkname (*Cipher).XORKeyStream vendor/golang.org/x/crypto/chacha20.(*Cipher).XORKeyStream
func (s *Cipher) XORKeyStream(dst, src []byte)

//go:linkname chacha20_NewUnauthenticatedCipher vendor/golang.org/x/crypto/chacha20.NewUnauthenticatedCipher
func chacha20_NewUnauthenticatedCipher(key, nonce []byte) (*Cipher, error)

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Splitter
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

//go:linkname poly1305_TagSize vendor/golang.org/x/crypto/chacha20.TagSize
const poly1305_TagSize = 16

//go:linkname MAC vendor/golang.org/x/crypto/chacha20.MAC
type MAC struct {}

//go:linkname (*MAC).Write vendor/golang.org/x/crypto/poly1305.(*MAC).Write
func (h *MAC) Write(p []byte) (n int, err error)

//go:linkname (*MAC).Sum vendor/golang.org/x/crypto/poly1305.(*MAC).Sum
func (h *MAC) Sum(b []byte) []byte

//go:linkname (*MAC).Verify vendor/golang.org/x/crypto/poly1305.(*MAC).Verify
func (h *MAC) Verify(expected []byte) bool

//go:linkname poly1305_New vendor/golang.org/x/crypto/poly1305.New
func poly1305_New(key *[32]byte) *MAC

//go:linkname poly1305_Sum vendor/golang.org/x/crypto/poly1305.Sum 
func poly1305_Sum(out *[16]byte, m []byte, key *[32]byte)

//go:linkname poly1305_Verify vendor/golang.org/x/crypto/poly1305.Verify 
func poly1305_Verify(mac *[16]byte, m []byte, key *[32]byte) bool