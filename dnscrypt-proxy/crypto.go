package main

import (
	"bytes"
	crypto_rand "crypto/rand"
	"errors"
	"math/big"

	"github.com/jedisct1/dlog"
	"github.com/jedisct1/xsecretbox"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	NonceSize        = xsecretbox.NonceSize
	HalfNonceSize    = xsecretbox.NonceSize / 2
	TagSize          = xsecretbox.TagSize
	PublicKeySize    = 32
	QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseOverhead = len(ServerMagic) + NonceSize + TagSize
)

func pad(packet []byte, padSize int) []byte {
	var pad = make([]byte, padSize)
	pad[0] = 0x80
	packet = append(packet, pad[:]...)
	return packet
}

func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, errors.New("Invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, errors.New("Invalid padding (delimiter not found)")
		}
	}
}

func ComputeSharedKey(cryptoConstruction CryptoConstruction, secretKey *[32]byte, serverPk *[32]byte, providerName string) (sharedKey [32]byte) {
	if cryptoConstruction == XChacha20Poly1305 {
		var err error
		sharedKey, err = xsecretbox.SharedKey(*secretKey, *serverPk)
		if err != nil {
			dlog.Criticalf("[%v] weak public key", providerName)
		}
	} else {
		box.Precompute(&sharedKey, serverPk, secretKey)
	}
	return
}

func (proxy *Proxy) Encrypt(serverInfo *DNSCryptInfo, packet []byte, proto string) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	var publicKey *[PublicKeySize]byte
	nonce, clientNonce := make([]byte, NonceSize), make([]byte, HalfNonceSize)
	crypto_rand.Read(clientNonce)
	copy(nonce, clientNonce)
	if proxy.ephemeralKeys {
		//h := sha512.New512_256()
		//h.Write(clientNonce)
		//h.Write(proxy.proxySecretKey[:])
		var ephSk [32]byte
		//h.Sum(ephSk[:0])
		crypto_rand.Read(ephSk[:])
		var xPublicKey [PublicKeySize]byte
		x, err1 := curve25519.X25519(ephSk[:],curve25519.Basepoint)
		if err1 != nil {
			err = err1
			return
		}
		copy(xPublicKey[:], x)
		publicKey = &xPublicKey
		xsharedKey := ComputeSharedKey(serverInfo.Version, &ephSk, &serverInfo.ServerPk, serverInfo.Name)
		sharedKey = &xsharedKey
	} else {
		sharedKey = &serverInfo.SharedKey
		publicKey = &proxy.proxyPublicKey
	}
	
	minQuestionSize := QueryOverhead + len(packet)
	if minQuestionSize+1 > MaxDNSPacketSize -64 {
		err = errors.New("Question too large; cannot be padded")
		return
	}
	firstclass := 0 //tcp: a query sent over TCP can be shorter than the response.
	initS := ((minQuestionSize+64) & ^63)
	program_dbg_full_log("init size: %d", initS)
	if proto == "udp" {
		firstclass = Max(47, initS/64) //avoid TC="Truncated"
	} else {
		firstclass = initS/64
	}
	rangefc := 63 - firstclass
	m := new(big.Int).SetInt64(int64(rangefc))
	b1, _ := crypto_rand.Int(crypto_rand.Reader, m)
	random_size := (firstclass + int(b1.Int64())) * 64
	paddedLength :=  Min(MaxDNSUDPPacketSize, random_size)
	program_dbg_full_log("padding size: %d", paddedLength)
	encrypted = append(serverInfo.MagicQuery[:], publicKey[:]...)
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	padded := pad(packet, paddedLength - len(packet))
	if serverInfo.Version == XChacha20Poly1305 {
		encrypted = xsecretbox.Seal(encrypted, nonce, padded, sharedKey[:])
	} else {
		var xsalsaNonce [24]byte
		copy(xsalsaNonce[:], nonce)
		encrypted = secretbox.Seal(encrypted, padded, &xsalsaNonce, sharedKey)
	}
	return
}

func (proxy *Proxy) Decrypt(serverInfo *DNSCryptInfo, sharedKey *[32]byte, encrypted []byte, nonce []byte) ([]byte, error) {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
		len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) ||
		!bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
		return encrypted, errors.New("Invalid message size or prefix")
	}
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errors.New("Unexpected nonce")
	}
	var packet []byte
	var err error
	if serverInfo.Version == XChacha20Poly1305 {
		packet, err = xsecretbox.Open(nil, serverNonce, encrypted[responseHeaderLen:], sharedKey[:])
	} else {
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], serverNonce)
		var ok bool
		packet, ok = secretbox.Open(nil, encrypted[responseHeaderLen:], &xsalsaServerNonce, sharedKey)
		if !ok {
			err = errors.New("Incorrect tag")
		}
	}
	if err != nil {
		return encrypted, err
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < MinDNSPacketSize {
		return encrypted, errors.New("Incorrect padding")
	}
	return packet, nil
}
