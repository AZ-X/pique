package protocols

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/jedisct1/dlog"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/unclassified"
	
	"golang.org/x/crypto/salsa20/salsa"
)

const (
	ClientMagicLen   = 8
	ServerMagicLen   = 8
	PublicKeySize    = 32
	NonceSize        = unclassified.NonceSize
	HalfNonceSize    = unclassified.NonceSize / 2
	TagSize          = unclassified.TagSize
	QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseOverhead = ServerMagicLen + NonceSize + TagSize
)

type CryptoConstruction uint8

const (
	UndefinedConstruction CryptoConstruction = iota
	XSalsa20Poly1305
	XChacha20Poly1305
)

type DNSCrypt struct {
	Name               *string
	MagicQuery         [ClientMagicLen]byte
	ServerPk           [32]byte
	Version            CryptoConstruction
}

func CertMagic() []byte {
	return []byte{0x44, 0x4e, 0x53, 0x43}
}

func ServerMagic() []byte {
	return []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
}

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

func ComputeSharedKey(cryptoConstruction CryptoConstruction, scalar, serverPk *[PublicKeySize]byte, providerName *string) (sharedKey *[PublicKeySize]byte) {
	goto Go
Fault:
	dlog.Debugf("[%s] is using weak public key, the program will be panicked", *providerName)
	panic(*providerName + " weak public key")
Go:
	if xKey, err := unclassified.Curve25519_X25519(scalar[:], serverPk[:]); err != nil {
		goto Fault
	} else {
		sharedKey = new([PublicKeySize]byte)
		copy(sharedKey[:], xKey)
	}
	var zeros [16]byte
	if cryptoConstruction == XChacha20Poly1305 {
		if ccKey, err := unclassified.Chacha20_HChaCha20(sharedKey[:], zeros[:]); err != nil {
			goto Fault
		} else {
			copy(sharedKey[:], ccKey)
		}
	} else {
		salsa.HSalsa20(sharedKey, &zeros, sharedKey, &salsa.Sigma)
	}
	return
}

func Encrypt(serverInfo *DNSCrypt, packet []byte, proto string) (sharedKey *[PublicKeySize]byte, nonce *[NonceSize]byte, encrypted []byte, err error) {
	var publicKey *[PublicKeySize]byte = new([PublicKeySize]byte)
	nonce = new([NonceSize]byte)
	rand.Read(nonce[:HalfNonceSize])
	var scalar [PublicKeySize]byte
	rand.Read(scalar[:])
	var x []byte
	if x, err = unclassified.Curve25519_X25519(scalar[:], unclassified.Curve25519_Basepoint); err != nil {
		return
	} else {
		copy(publicKey[:], x)
	}
	sharedKey = ComputeSharedKey(serverInfo.Version, &scalar, &serverInfo.ServerPk, serverInfo.Name)

	minQuestionSize := QueryOverhead + len(packet)
	if minQuestionSize+1 > common.MaxDNSUDPPacketSize -64 {
		err = errors.New("Question too large; cannot be padded")
		return
	}
	firstclass := 0 //tcp: a query sent over TCP can be shorter than the response.
	initS := ((minQuestionSize+64) & ^63)
	common.Program_dbg_full_log("init size: %d", initS)
	if proto == "udp" {
		firstclass = common.Max(47, initS/64) //avoid TC="Truncated"
	} else {
		firstclass = initS/64
	}
	rangefc := 63 - firstclass
	m := new(big.Int).SetInt64(int64(rangefc))
	b1, _ := rand.Int(rand.Reader, m)
	random_size := (firstclass + int(b1.Int64())) * 64
	paddedLength :=  common.Min(common.MaxDNSUDPPacketSize, random_size)
	common.Program_dbg_full_log("padding size: %d", paddedLength)
	encrypted = append(serverInfo.MagicQuery[:], publicKey[:]...)
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	padded := pad(packet, paddedLength - len(packet))
	if serverInfo.Version == XChacha20Poly1305 {
		encrypted = unclassified.SealX(encrypted, nonce[:], padded, sharedKey[:])
	} else {
		encrypted = unclassified.Seal(encrypted, padded, nonce, sharedKey)
	}
	return
}

func Decrypt(serverInfo *DNSCrypt, sharedKey *[32]byte, encrypted []byte, nonce *[NonceSize]byte, proto string) ([]byte, error) {
	responseHeaderLen := ServerMagicLen + NonceSize
	var maxDNSPacketSize int64
	if proto == "udp" {
		maxDNSPacketSize = common.MaxDNSUDPPacketSize
	} else {
		maxDNSPacketSize = common.MaxDNSPacketSize
	}
	if len(encrypted) < responseHeaderLen+TagSize+int(common.MinDNSPacketSize) ||
		len(encrypted) > responseHeaderLen+TagSize+int(maxDNSPacketSize) ||
		!bytes.Equal(encrypted[:ServerMagicLen], ServerMagic()) {
		return encrypted, errors.New("Invalid message size or prefix")
	}
	serverNonce := encrypted[ServerMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errors.New("Unexpected nonce")
	}
	var packet []byte
	var err error
	if serverInfo.Version == XChacha20Poly1305 {
		packet, err = unclassified.OpenX(nil, serverNonce, encrypted[responseHeaderLen:], sharedKey[:])
	} else {
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], serverNonce)
		var ok bool
		packet, ok = unclassified.Open(nil, encrypted[responseHeaderLen:], &xsalsaServerNonce, sharedKey)
		if !ok {
			err = errors.New("Incorrect tag")
		}
	}
	if err != nil {
		return encrypted, err
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < common.MinDNSPacketSize {
		return encrypted, errors.New("Incorrect padding")
	}
	return packet, nil
}
