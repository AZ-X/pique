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
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/AZ-X/dns"
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
	ClientMagicLen     = 8
	ServerMagicLen     = 8
	AnonymizedOverhead = 28
	PublicKeySize      = 32
	SharedKeySize      = PublicKeySize
	NonceSize          = unclassified.NonceSize
	HalfNonceSize      = unclassified.NonceSize / 2
	TagSize            = unclassified.TagSize
	QueryOverhead      = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseHeaderLen  = ServerMagicLen + NonceSize
	ResponseOverhead   = ResponseHeaderLen + TagSize
	IdentifierPrefix   = "2.dnscrypt-cert."
	DNSRoot            = "."
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
	V1_Services        *atomic.Value //[]*ServiceInfo
	V2_Services        *atomic.Value //[]*ServiceInfo
	VN_Services        *atomic.Value //[]*ServiceInfo
}

type ServiceInfo struct {
	*Service
	Minor              uint16
	Regular            uint16 //A.K.A period of key rotation in hours if exists
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

func (r *Resolver) GetServices() (sis []*ServiceInfo, operable uint8, minRegular uint16) {
	for _, si := range func () []*ServiceInfo {
		if sis = r.V2_Services.Load().([]*ServiceInfo); len(sis) != 0 {
		return sis
		} else if sis = r.V1_Services.Load().([]*ServiceInfo); len(sis) != 0 {
		return sis
		}
		return nil}() {
		if time.Now().Before(time.Unix(int64(si.DtTo), 0)) {
			operable++
		}
		if si.Regular != 0 && (minRegular == 0 || minRegular > si.Regular) {
			minRegular = si.Regular
		}
	}
	return
}

func (r *Resolver) GetDefaultService() (s *ServiceInfo) {
	if s, _, _ := r.GetServices(); s != nil {
		return s[0]
	}
	return
}

func (r *Resolver) GetRandomService() *ServiceInfo {
	if s, op, _ := r.GetServices(); op > 1 {
		c := make(chan uint8, 1)
		defer close(c)
		select {
		case c <- 1:
		case c <- 2:
		case c <- 3:
		case c <- 4:
		case c <- 5:
		case c <- 6:
		}
		return s[<-c%op]
	} else if op == 1 {
		return s[0]
	}
	return nil
}

func (r *Resolver) GetDefaultExpiration() time.Time {
	if s := r.GetDefaultService(); s != nil {
		return time.Unix(int64(s.DtTo), 0).Local()
	}
	return time.Now()
}

func (r *Resolver) GetExpirationAdvanced() time.Time {
	if s, op, minR := r.GetServices(); op > 1 {
		f := time.Unix(int64(s[0].DtFrom), 0)
		d := time.Since(f).Truncate(time.Duration(minR) * time.Hour)
		var m uint16
		if d <= 0 {
			m =1 
		} else {
			m = uint16(d / (time.Duration(minR) * time.Hour))
			if time.Now().After(f.Add(time.Duration(m * minR) * time.Hour + time.Minute)) {
				m++
			}
		}
		//go sucks
		return func(x, y time.Time) time.Time {if x.Compare(y) != -1 {return y }; return x } (time.Unix(int64(s[0].DtTo), 0), f.Add(time.Duration(minR * m) * time.Hour)).Local()
	} else if s!= nil {
		return time.Unix(int64(s[0].DtTo), 0).Local()
	}
	return time.Now()
}


func RetrieveServicesInfo(useSk bool, resolver *Resolver, dialFn common.DialFn, proto string, upstreamAddr *common.Endpoint, relays *[]*common.Endpoint) (time.Duration, error) {
	if len(resolver.PublicKey) != ed25519.PublicKeySize {
		return 0, errors.New("invalid public key length -> " + *resolver.Name)
	}
	var rtt time.Duration
	var err error
	var service *Service
	if useSk {
		service = resolver.GetDefaultService().Service
	}
	var v1_Services []*ServiceInfo
	var v2_Services []*ServiceInfo
	var vn_Services []*ServiceInfo
	var keys map[ServerKey]interface{} = make(map[ServerKey]interface{})
RowLoop:
	for _, str := range resolver.Identifiers {
		var binResult *[]byte
		var preResult *[]byte
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
				now := time.Now()
				binResult, err = Query(dialFn, proto, service, &binQuery, upstreamAddr, relayAddr)
				rtt = time.Since(now)
				if err != nil {
					dlog.Debug(err)
					dlog.Noticef("relay [%d] failed for [%s]", i + 1, *resolver.Name)
					binResult = preResult
					continue
				}
				if preResult != nil && !bytes.Equal(*binResult, *preResult) {
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
			now := time.Now()
			if binResult, err = Query(dialFn, proto, service, &binQuery, upstreamAddr, nil); err != nil {
				dlog.Debug(err)
				continue
			}
			rtt = time.Since(now)
		}
		msg := new(dns.Msg)
		if err = msg.Unpack_TS(*binResult, map[uint16]func()dns.RR{}); err != nil {
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
			// below works with msg.Unpack
			//lenData := int(rr.Header().Rdlength)
			//lenRR := dns.Len(rr)
			//var binCert []byte = make([]byte, lenRR)
			//var off int
			//off, _ = dns.PackRR(rr, binCert, 0, nil, false)
			//binCert = binCert[off - lenData + 1:off]
			/*
			A single text DNS record (either TXT or SPF RR types) can be composed of more than one string.
			If a published record contains multiple strings,
			then the record MUST be treated as if those strings are concatenated together without adding spaces.
			*/
			rd := rr.(*dns.UnknownRR).Rdata
			var binCert []byte
			for next_l := 0; next_l < len(rd); next_l = next_l+1+int(rd[next_l]) {
				if next_l+1+int(rd[next_l]) > len(rd) {
					err = dlog.Errorf("certificate of [%v] is corrupt, stop using it", *resolver.Name)
					return 0, err
				}
				binCert = append(binCert, rd[next_l+1:next_l+1+int(rd[next_l])]...)
			}
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
	if len(resolver.V1_Services.Load().([]*ServiceInfo)) != 0 ||
		len(resolver.V2_Services.Load().([]*ServiceInfo)) != 0 ||
		len(resolver.VN_Services.Load().([]*ServiceInfo)) != 0 {
		deleted := make(map[ServerKey]interface{})
		l := len(keys)
		visitFn := func(sis []*ServiceInfo, sis0 *[]*ServiceInfo) {
			for _, si := range sis {
				if _, found := keys[*si.ServerKey]; !found {
					deleted[*si.ServerKey] = nil
					*sis0 = append(*sis0, si)
				} else {
					delete(keys, *si.ServerKey)
				}
			}
		}
		visitFn(resolver.V1_Services.Load().([]*ServiceInfo), &v1_Services)
		visitFn(resolver.V2_Services.Load().([]*ServiceInfo), &v2_Services)
		visitFn(resolver.VN_Services.Load().([]*ServiceInfo), &vn_Services)
		dlog.Infof("[%s] public key re-engage: added=%d deleted=%d unchanged=%d", *resolver.Name, len(keys), len(deleted), l-len(keys))
	}
	sortF := func(sis []*ServiceInfo) {
		sort.Slice(sis, func(i, j int) bool {
		return sis[i].Serial > sis[j].Serial || (sis[i].Serial == sis[j].Serial && sis[i].DtTo > sis[j].DtTo )
		})
		for idx, si := range sis {
			from := time.Unix(int64(si.DtFrom), 0).UTC()
			to := time.Unix(int64(si.DtTo), 0).UTC()
			d := to.Sub(from)
			checkdt := func(d time.Duration) {
				if d <= 0 || d > 15 * 24 * time.Hour {
				panic("stop using it! malformed datetime represented of " + *resolver.Name)
				}
			}
			checkdt(d)
			if idx == 0 {
				checkdt(time.Until(to))
			}
			if idx > 0 {
				from1 := time.Unix(int64(sis[idx-1].DtFrom), 0).UTC()
				to1 := time.Unix(int64(sis[idx-1].DtTo), 0).UTC()
				if from == from1 && to == to1 {
					dlog.Warnf("[%s] sk1: %v-%v sk2: %v-%v", *resolver.Name, si.MagicQuery, si.ServerPk, sis[idx-1].MagicQuery, sis[idx-1].ServerPk)
				}
				si.Regular = uint16((time.Duration(sis[idx-1].DtFrom - si.DtFrom) * time.Second).Truncate(time.Hour).Hours())
			}
			dlog.Infof("[%s] public key info: ver=%d.%d serial=%d from=%d/%v/%v+%.2v:%.2vUTC to=%d/%v/%v+%.2v:%.2vUTC len_ext=%d R=%dH", *resolver.Name,
			si.Version, si.Minor, si.Serial,
			from.Month(), from.Day(), from.Year(), from.Hour(), from.Minute(),
			to.Month(), to.Day(), to.Year(), to.Hour(), to.Minute(),
			len(si.Ext), si.Regular)
			if idx > 0 {
				sis[idx-1].Regular = si.Regular // shift after print info
				si.Regular = 0
			}
		}
	}
	sortF(v1_Services)
	sortF(v2_Services)
	sortF(vn_Services)
	if len(v1_Services) > 255 || len(v2_Services) > 255 || len(vn_Services) > 255 {
		err = dlog.Errorf("got malformed dns answer for [%s]", *resolver.Name)
		return 0, err
	}
	resolver.V1_Services.Store(v1_Services)
	resolver.V2_Services.Store(v2_Services)
	resolver.VN_Services.Store(vn_Services)
	return rtt, err
}

// looks like a standard dns query via user-defined port, nevertheless it's fixed with fingerprints
func Query(dialFn common.DialFn, proto string, service *Service, bin *[]byte, upstreamAddr, relayAddr *common.Endpoint) (*[]byte, error) {
	var err error
	goto Go
Error:
	return nil, err
Go:
	var sharedKey *[PublicKeySize]byte
	var nonce *[NonceSize]byte

	binLength := len(*bin)
	if service != nil {
		if binLength, err = calcDynamicEncryptedPaddingSize(binLength, proto); err != nil {
			goto Error
		}
	}
	var buf []byte
	var pbuf *[]byte
	if relayAddr != nil {
		buf = make([]byte, 0, binLength + AnonymizedOverhead)
		buf = append(buf, AnonymizedDNSHeader()...)
		buf = append(buf, upstreamAddr.IP.To16()...)
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[0:2], uint16(upstreamAddr.Port))
		buf = append(buf, tmp[:]...)
		sbuf := buf[AnonymizedOverhead:]
		pbuf = &sbuf
		upstreamAddr = relayAddr
	} else {
		buf = make([]byte, 0, binLength)
		pbuf = &buf
	}
	if service != nil {
		sharedKey, nonce, err = encrypt(service, bin, pbuf, proto)
	} else {
		buf = append(buf, *bin...)
	}
	buf = buf[:cap(buf)]
	if err != nil {
		common.Program_dbg_full_log("dnscrypt Query E01")
		goto Error
	}

	var pc net.Conn
	pc, err = dialFn(proto, upstreamAddr.String())
	if err != nil {
		common.Program_dbg_full_log("dnscrypt Query E02")
		goto Error
	}
	defer pc.Close()
	var packet []byte
	for tries := 2; tries > 0; tries-- {
		if err = common.WriteDP(pc, buf); err != nil {
			common.Program_dbg_full_log(err.Error())
			common.Program_dbg_full_log("dnscrypt Query E03")
			continue
		}
		if packet, err = common.ReadDP(pc); err == nil {
			break
		}
		common.Program_dbg_full_log("retry on Timeout or <-EOF msg")
	}
	if err != nil {
		common.Program_dbg_full_log("dnscrypt Query E04")
		goto Error
	}
	if service != nil {
		packet, err = decrypt(service.Version, sharedKey, packet, nonce, proto)
	}
	return &packet, err
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
			return nil, errors.New("invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, errors.New("invalid padding (delimiter not found)")
		}
	}
}

func deriveSharedKey(cryptoConstruction CryptoConstruction, scalar, serverPk *[PublicKeySize]byte, name *string) (sharedKey *[PublicKeySize]byte) {
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

func calcDynamicEncryptedPaddingSize(length int, proto string) (eLength int, err error) {
	minQuestionSize := QueryOverhead + length
	if minQuestionSize+1 > common.MaxDNSUDPPacketSize -64 {
		err = errors.New("data too large; cannot be padded")
		return
	}
	firstclass := 0 //tcp: a query sent over TCP can be shorter than the response.
	initS := ((minQuestionSize+64) & ^63)
	common.Program_dbg_full_log("init size: %d", initS)
	if proto == "udp" {
		firstclass = max(47, initS/64) //avoid TC="Truncated"
	} else {
		firstclass = initS/64
	}
	rangefc := 63 - firstclass
	m := new(big.Int).SetInt64(int64(rangefc))
	b1, _ := rand.Int(rand.Reader, m)
	random_size := (firstclass + int(b1.Int64())) * 64
	paddedLength :=  min(common.MaxDNSUDPPacketSize, random_size)
	common.Program_dbg_full_log("padding size: %d", paddedLength)
	eLength = QueryOverhead + paddedLength
	common.Program_dbg_full_log("encrypted size: %d", eLength)
	return
}

func encrypt(service *Service, packet, buf *[]byte, proto string) (sharedKey *[PublicKeySize]byte, nonce *[NonceSize]byte, err error) {
	encrypted := *buf
	_packet := *packet
	eLength := cap(encrypted)
	padded := pad(_packet, eLength - QueryOverhead - len(_packet))
	var scalar [PublicKeySize]byte
	rand.Read(scalar[:])
	var xPK []byte
	if xPK, err = unclassified.Curve25519_X25519(scalar[:], unclassified.Curve25519_Basepoint); err != nil {
		return
	}
	if len(xPK) != PublicKeySize {
		panic("X25519 failed to return a slice of 32 bytes")
	}
	encrypted = append(encrypted, service.MagicQuery[:]...)
	encrypted = append(encrypted, xPK[:]...)
	nonce = new([NonceSize]byte)
	rand.Read(nonce[:HalfNonceSize])
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	sharedKey = deriveSharedKey(service.Version, &scalar, &service.ServerPk, service.Name)
	if service.Version == XChacha20Poly1305 {
		encrypted = unclassified.SealX(encrypted, nonce[:], padded, sharedKey[:])
	} else {
		encrypted = unclassified.Seal(encrypted, padded, nonce, sharedKey)
	}
	if len(encrypted) != eLength {
		panic("dnscrypt encryption is unpredictable")
	}
	return
}

func decrypt(version CryptoConstruction, sharedKey *[SharedKeySize]byte, encrypted []byte, nonce *[NonceSize]byte, proto string) ([]byte, error) {
	var maxDNSPacketSize int64
	if proto == "udp" {
		maxDNSPacketSize = common.MaxDNSUDPPacketSize
	} else {
		maxDNSPacketSize = common.MaxDNSPacketSize
	}
	if len(encrypted) < ResponseOverhead+int(common.MinDNSPacketSize) ||
		len(encrypted) > ResponseOverhead+int(maxDNSPacketSize) ||
		!bytes.Equal(encrypted[:ServerMagicLen], ServerMagic()) {
		return encrypted, errors.New("invalid message size or prefix")
	}
	serverNonce := encrypted[ServerMagicLen:ResponseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errors.New("unexpected nonce")
	}
	var packet []byte
	var err error
	if version == XChacha20Poly1305 {
		packet, err = unclassified.OpenX(nil, serverNonce, encrypted[ResponseHeaderLen:], sharedKey[:])
	} else {
		var xsalsaServerNonce [NonceSize]byte
		copy(xsalsaServerNonce[:], serverNonce)
		packet, err = unclassified.Open(nil, encrypted[ResponseHeaderLen:], &xsalsaServerNonce, sharedKey)
	}
	if err != nil {
		return nil, err
	}
	if len(encrypted) != len(packet)+ResponseOverhead  {
		panic("dnscrypt decryption is unpredictable")
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < common.MinDNSPacketSize {
		return encrypted, errors.New("incorrect padding of dnscrypt packet")
	}
	return packet, nil
}
