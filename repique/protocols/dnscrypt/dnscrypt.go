package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"golang.org/x/crypto/salsa20/salsa"

	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/unclassified"
)

/*

No issuer no certification
No purpose no certification
No verification chain no certification
**********************************************
in DNSCRYPT-V2-PROTOCOL.txt:
'provider name' should be known as identifiers
'cert' should be known as public key extensions based on well-known PKI

dnscrypt.go wraps all these oddments of 'DNSCRYPT-V2-PROTOCOL' into a single reusable file
however it still depends on dboy, common and unclassified getting at a reflection of what it was
*THIS IS THE MOST FLEXIBLE AND STRONG IMPLEMENTATION IN THE WORLD*
*NOW THE QUESTION IS IF THINGS CAN BE DONE IN THIS WAY, WHY IT GOES TO OTHER WAY*

*/



const (
	ClientMagicLen   = 8
	ServerMagicLen   = 8
	PublicKeySize    = 32
	SharedKeySize    = PublicKeySize
	NonceSize        = unclassified.NonceSize
	HalfNonceSize    = unclassified.NonceSize / 2
	TagSize          = unclassified.TagSize
	QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseOverhead = ServerMagicLen + NonceSize + TagSize
	IdentifierPrefix = "2.dnscrypt-cert."
	DNSRoot          = "."
)

type CryptoConstruction uint8

const (
	UndefinedConstruction CryptoConstruction = iota
	XSalsa20Poly1305
	XChacha20Poly1305
)
//these are the fingerprint of the dnscrypt protocols, keep in mind
func CertMagic() []byte {
	return []byte{0x44, 0x4e, 0x53, 0x43}
}

func ServerMagic() []byte {
	return []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
}

func AnonymizedDNSHeader() []byte {
	return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
}

type Resolver struct {
	Name               *string
	Identifiers        []string
	PublicKey          ed25519.PublicKey
	V1_Services        []*ServiceInfo
	V2_Services        []*ServiceInfo
	VN_Services        []*ServiceInfo
}

type ServiceInfo struct {
	*Service
	Minor              uint16
	Serial             uint32
	DtFrom             uint32
	DtTo               uint32
	Ext                []byte
}

type Service struct {
	*ServerKey
	Name               *string
	Version            CryptoConstruction
}

type ServerKey struct {
	MagicQuery         [ClientMagicLen]byte
	ServerPk           [PublicKeySize]byte
}

func RetrieveServicesInfo(useSk bool, resolver *Resolver, dialFn common.DialFn, proto string, upstreamAddr *common.Endpoint, relays *[]*common.Endpoint) (time.Duration, error) {
	if len(resolver.PublicKey) != ed25519.PublicKeySize {
		return 0, errors.New("invalid public key length -> " + *resolver.Name)
	}
	var rtt time.Duration
	var err error
	var service *Service
	if useSk && len(resolver.V2_Services) != 0 {
		service = resolver.V2_Services[0].Service
	} else if len(resolver.V1_Services) != 0 {
		service = resolver.V1_Services[0].Service
	}
	var v1_Services []*ServiceInfo
	var v2_Services []*ServiceInfo
	var vn_Services []*ServiceInfo
	var keys map[ServerKey]interface{} = make(map[ServerKey]interface{})
RowLoop:
	for _, str := range resolver.Identifiers {
		var binResult []byte
		var preResult []byte
		identifier := str
		if !strings.HasSuffix(identifier, DNSRoot) {
			identifier = identifier + DNSRoot
		}
		if !strings.HasPrefix(identifier, IdentifierPrefix) {
			dlog.Warnf("[%s] uses a non-standard provider name '%s'", *resolver.Name, identifier)
		}
		query := &dns.Msg{}
		query.SetQuestion(identifier, dns.TypeTXT)
		query.Id = 0
		if proto == "udp" {
			padding := common.MaxDNSUDPSafePacketSize - query.Len()
			opt := new(dns.OPT)
			opt.Hdr.Name = DNSRoot
			ext := new(dns.EDNS0_PADDING)
			ext.Padding = make([]byte, padding)
			opt.Option = append(opt.Option, ext)
			query.Extra = []dns.RR{opt}
		}
		var binQuery []byte
		binQuery, err = query.Pack()
		if err != nil {
			return 0, err
		}
		var working_relays []*common.Endpoint
		_relays := *relays
		if len(_relays) > 0 {
			for i , relayAddr := range _relays {
				binResult, rtt, err = Query(dialFn, proto, service, binQuery, upstreamAddr, relayAddr)
				if err != nil {
					dlog.Debug(err)
					dlog.Noticef("relay [%d] failed for [%s]", i + 1, *resolver.Name)
					continue
				}
				if preResult != nil && !bytes.Equal(binResult, preResult) {
					err = dlog.Errorf("relay [%d] returns unmatched result for [%s]", i + 1, *resolver.Name)
					continue RowLoop
				}
				preResult = binResult
				working_relays = append(working_relays, relayAddr)
			}
			if len(working_relays) < 1 {
				err = dlog.Errorf("all relays failed for [%s]", *resolver.Name)
				continue RowLoop
			}
			*relays = working_relays
		} else {
			binResult, rtt, err = Query(dialFn, proto, service, binQuery, upstreamAddr, nil)
		}
		if err != nil {
			dlog.Debug(err)
			continue
		}
		msg := new(dns.Msg)
		if err = msg.Unpack(binResult); err != nil {
			dlog.Debug(err)
			dlog.Errorf("got corrupt dns format for [%s]", *resolver.Name)
			continue
		}
		if !msg.Response || msg.Truncated || msg.Rcode != dns.RcodeSuccess {
			err = dlog.Errorf("got wrong msg status for [%s] = %v %v %v", *resolver.Name, msg.Response, msg.Truncated, msg.Rcode)
			continue
		}
		hasTXT := false
		for _, rr := range msg.Answer {
			if rr.Header().Rrtype != dns.TypeTXT {
				err = dlog.Errorf("[%s] extra record of type [%v] found in certificate", *resolver.Name, rr.Header().Rrtype)
				continue
			}
			hasTXT = true
			lenData := int(rr.Header().Rdlength)
			lenRR := dns.Len(rr)
			var binCert []byte = make([]byte, lenRR)
			var off int
			off, _ = dns.PackRR(rr, binCert, 0, nil, false)
			binCert = binCert[off - lenData + 1:off]
			if len(binCert) < 124 {
				err = dlog.Errorf("certificate of [%v] is too short", *resolver.Name)
				continue
			}
			if !bytes.Equal(binCert[:4], CertMagic()) {
				err = dlog.Errorf("[%s] has invalid cert magic", *resolver.Name)
				continue
			}
			signature := binCert[8:72]
			signed := binCert[72:]
			if !ed25519.Verify(resolver.PublicKey, signed, signature) {
				err = dlog.Errorf("[%s] incorrect signature for name: '%v'", *resolver.Name, identifier)
				continue
			}
			si := &ServiceInfo{Ext:make([]byte, len(binCert) - 124)}
			si.Service = &Service{Name:resolver.Name, ServerKey:&ServerKey{MagicQuery:*new([ClientMagicLen]byte), ServerPk:*new([PublicKeySize]byte)}}
			si.Name = resolver.Name
			si.Minor = binary.BigEndian.Uint16(binCert[6:8])
			si.Serial = binary.BigEndian.Uint32(binCert[112:116])
			si.DtFrom = binary.BigEndian.Uint32(binCert[116:120])
			si.DtTo = binary.BigEndian.Uint32(binCert[120:124])
			copy(si.MagicQuery[:], binCert[104:112])
			copy(si.ServerPk[:], binCert[72:104])
			if _, duplicate := keys[*si.ServerKey]; duplicate {
				return 0, errors.New("duplicate public key found -> " + *resolver.Name)
			}
			keys[*si.ServerKey] = nil
			copy(si.Ext[:], binCert[124:])
			switch binary.BigEndian.Uint16(binCert[4:6]) {
			case 0x0001:
				si.Version = XSalsa20Poly1305
				v1_Services = append(v1_Services, si)
			case 0x0002:
				si.Version = XChacha20Poly1305
				v2_Services = append(v2_Services, si)
			default:
				si.Version = UndefinedConstruction
				vn_Services = append(vn_Services, si)
				err = dlog.Errorf("[%s] has unsupported crypto construction", *resolver.Name)
			}
		}
		if !hasTXT {
			return 0, errors.New("fault server missing TXT record -> " + *resolver.Name)
		}
	}
	if len(v2_Services) != 0 || len(v1_Services) != 0 {
		err = nil
	}
	if err != nil {
		return 0, err
	}
	if len(resolver.V1_Services) != 0 || len(resolver.V2_Services) != 0 || len(resolver.VN_Services) != 0 {
		deleted := make(map[ServerKey]interface{})
		visitFn := func(sis []*ServiceInfo, sis0 []*ServiceInfo) {
			for _, si := range sis {
				if _, found := keys[*si.ServerKey]; !found {
					deleted[*si.ServerKey] = nil
					sis0 = append(sis0, si)
				} else {
					delete(keys, *si.ServerKey)
				}
			}
		}
		visitFn(resolver.V1_Services, v1_Services)
		visitFn(resolver.V2_Services, v2_Services)
		visitFn(resolver.VN_Services, vn_Services)
		dlog.Infof("[%s] public key re-engage: added=%d deleted=%d", *resolver.Name, len(keys), len(deleted))
	}
	sortF := func(sis []*ServiceInfo) {
		sort.Slice(sis, func(i, j int) bool {
		return sis[i].Serial > sis[j].Serial
		})
		for _, si := range sis {
			from := time.Unix(int64(si.DtFrom), 0).UTC()
			to := time.Unix(int64(si.DtTo), 0).UTC()
			dlog.Infof("[%s] public key info: ver=%d.%d serial=%d from=UTC%v-%d-%v+%.2v:%.2v to=UTC%v-%d-%v+%.2v:%.2v len_ext=%d", *resolver.Name,
			si.Version, si.Minor, si.Serial,
			from.Year(), from.Month(), from.Day(), from.Hour(), from.Minute(),
			to.Year(), to.Month(), to.Day(), to.Hour(), to.Minute(),
			len(si.Ext))
		}
	}
	sortF(v1_Services)
	sortF(v2_Services)
	sortF(vn_Services)
	resolver.V1_Services = v1_Services
	resolver.V2_Services = v2_Services
	resolver.VN_Services = vn_Services
	return rtt, err
}

// looks like a standard dns query via user-defined port, nevertheless it's fixed with fingerprints
func Query(dialFn common.DialFn, proto string, service *Service, bin []byte, upstreamAddr, relayAddr *common.Endpoint) ([]byte, time.Duration, error) {
	var err error
	var rtt time.Duration
	goto Go
Error:
	return nil, rtt, err
Go:
	var sharedKey *[PublicKeySize]byte
	var nonce *[NonceSize]byte

	binQuery := &bin
	var pc net.Conn
	if service != nil {
		sharedKey , nonce, binQuery, err = encrypt(service, binQuery, proto)
	}
	if err != nil {
		common.Program_dbg_full_log("dnscrypt Query E01")
		goto Error
	}
	if relayAddr != nil {
		appendReHeader(upstreamAddr, binQuery)
		upstreamAddr = relayAddr
	}
	now := time.Now()
	pc, err = dialFn(proto, upstreamAddr.String())
	if err != nil {
		common.Program_dbg_full_log("dnscrypt Query E02")
		goto Error
	}
	defer pc.Close()
	var packet []byte
	for tries := 2; tries > 0; tries-- {
		if err = common.WriteDP(pc, *binQuery); err != nil {
			common.Program_dbg_full_log(err.Error())
			common.Program_dbg_full_log("dnscrypt Query E03")
			continue
		}
		if packet, err = common.ReadDP(pc); err == nil {
			break
		}
		common.Program_dbg_full_log("retry on Timeout or <-EOF msg")
	}
	rtt = time.Since(now)
	if err != nil {
		common.Program_dbg_full_log("dnscrypt Query E04")
		goto Error
	}
	if service != nil {
		packet, err = decrypt(service.Version, sharedKey, packet, nonce, proto)
	}
	return packet, rtt, err
}

func appendReHeader(endpoint *common.Endpoint, bin *[]byte) {
	relayedQuery := append(AnonymizedDNSHeader(), endpoint.IP.To16()...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(endpoint.Port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *bin...)
	*bin = relayedQuery
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

func computeSharedKey(cryptoConstruction CryptoConstruction, scalar, serverPk *[PublicKeySize]byte, name *string) (sharedKey *[PublicKeySize]byte) {
	goto Go
Fault:
	dlog.Warnf("[%s] is using weak public key, the program will be panicked", *name)
	panic(*name + " weak public key")
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

func encrypt(service *Service, packet *[]byte, proto string) (sharedKey *[PublicKeySize]byte, nonce *[NonceSize]byte, encrypted *[]byte, err error) {
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
	sharedKey = computeSharedKey(service.Version, &scalar, &service.ServerPk, service.Name)
	_packet := *packet
	minQuestionSize := QueryOverhead + len(_packet)
	if minQuestionSize+1 > common.MaxDNSUDPPacketSize -64 {
		err = errors.New("data too large; cannot be padded")
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
	_encrypted := append(service.MagicQuery[:], publicKey[:]...)
	_encrypted = append(_encrypted, nonce[:HalfNonceSize]...)
	padded := pad(_packet, paddedLength - len(_packet))
	if service.Version == XChacha20Poly1305 {
		_encrypted = unclassified.SealX(_encrypted, nonce[:], padded, sharedKey[:])
	} else {
		_encrypted = unclassified.Seal(_encrypted, padded, nonce, sharedKey)
	}
	encrypted = &_encrypted
	return
}

func decrypt(version CryptoConstruction, sharedKey *[SharedKeySize]byte, encrypted []byte, nonce *[NonceSize]byte, proto string) ([]byte, error) {
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
	if version == XChacha20Poly1305 {
		packet, err = unclassified.OpenX(nil, serverNonce, encrypted[responseHeaderLen:], sharedKey[:])
	} else {
		var xsalsaServerNonce [NonceSize]byte
		copy(xsalsaServerNonce[:], serverNonce)
		var ok bool
		packet, ok = unclassified.Open(nil, encrypted[responseHeaderLen:], &xsalsaServerNonce, sharedKey)
		if !ok {
			err = errors.New("incorrect tag")
		}
	}
	if err != nil {
		return encrypted, err
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < common.MinDNSPacketSize {
		return encrypted, errors.New("incorrect padding")
	}
	return packet, nil
}
