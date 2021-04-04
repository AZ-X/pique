package unclassified

import (
	"errors"
)

const (
	// KeySize is what the name suggests
	KeySize = 32
	// NonceSize is what the name suggests
	NonceSize = 24
	// TagSize is what the name suggests
	TagSize = poly1305_TagSize
)


// Seal does what the name suggests
func SealX(out, nonce, message, key []byte) []byte {
	if len(nonce) != NonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != KeySize {
		panic("unsupported key size")
	}

	var firstBlock [64]byte
	cipher, _ := chacha20_NewUnauthenticatedCipher(key, nonce)
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [KeySize]byte
	copy(polyKey[:], firstBlock[:KeySize])

	ret, out := sliceForAppend(out, TagSize+len(message))
	if anyOverlap(out, message) {
		panic("nacl: invalid buffer overlap")
	}
	firstMessageBlock := message
	if len(firstMessageBlock) > KeySize {
		firstMessageBlock = firstMessageBlock[:KeySize]
	}

	tagOut := out
	out = out[TagSize:]
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[KeySize+i] ^ x
	}
	message = message[len(firstMessageBlock):]
	ciphertext := out
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, message)

	var tag [TagSize]byte
	hash := poly1305_New(&polyKey)
	hash.Write(ciphertext)
	hash.Sum(tag[:0])
	copy(tagOut, tag[:])

	return ret
}

// OpenX authenticates and decrypts a box produced by SealX and appends the
// message to out, which must not overlap box. The output will be Overhead
// bytes smaller than box.
func OpenX(out, nonce, box, key []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != KeySize {
		panic("unsupported key size")
	}
	if len(box) < Overhead {
		return nil, errors.New("ciphertext is too short")
	}

	var firstBlock [64]byte
	cipher, _ := chacha20_NewUnauthenticatedCipher(key, nonce)
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])

	var polyKey [KeySize]byte
	copy(polyKey[:], firstBlock[:KeySize])
	ciphertext := box[Overhead:]

	hash := poly1305_New(&polyKey)
	hash.Write(ciphertext)

	if !hash.Verify(box[:Overhead]) {
		return nil, errors.New("OpenX:ciphertext authentication failed")
	}

	ret, out := sliceForAppend(out, len(ciphertext))
	if anyOverlap(out, box) {
		panic("nacl: invalid buffer overlap")
	}

	firstMessageBlock := ciphertext
	if len(firstMessageBlock) > KeySize {
		firstMessageBlock = firstMessageBlock[:KeySize]
	}
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[KeySize+i] ^ x
	}
	ciphertext = ciphertext[len(firstMessageBlock):]
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, ciphertext)
	return ret, nil
}

