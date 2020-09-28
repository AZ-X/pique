package stammel

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const DefaultPort = 443

type ServerInformalProperties uint64

const (
	ServerInformalPropertyDNSSEC   = ServerInformalProperties(1) << 0
	ServerInformalPropertyNoLog    = ServerInformalProperties(1) << 1
	ServerInformalPropertyNoFilter = ServerInformalProperties(1) << 2
)

type StampProtoType uint8

const (
	_                           = StampProtoType(0x00)
	StampProtoTypeDNSCrypt      = StampProtoType(0x01)
	StampProtoTypeDoH           = StampProtoType(0x02)
	StampProtoTypeTLS           = StampProtoType(0x03)
	StampProtoTypeDoTEx         = StampProtoType(0x45)
	StampProtoTypeDoHEx         = StampProtoType(0x69)
	StampProtoTypeProxy         = StampProtoType(0x96) // HTTPS Proxy; SOCKS 5 Proxy;
	StampProtoTypeDNSCryptRelay = StampProtoType(0x81)
	StampProtoTypeDNSCryptEx    = StampProtoType(0xA9)
)

func (stampProtoType *StampProtoType) String() string {
	switch *stampProtoType {
	case StampProtoTypeDoH, StampProtoTypeDoHEx:
		return "DoH"
	case StampProtoTypeTLS, StampProtoTypeDoTEx:
		return "DoT"
	case StampProtoTypeDNSCrypt, StampProtoTypeDNSCryptEx:
		return "DNSCrypt"
	case StampProtoTypeDNSCryptRelay:
		return "Anonymized DNSCrypt"
	case StampProtoTypeProxy:
		return "Proxy"
	default:
		panic("Unexpected protocol")
	}
}

type HEXJSON []uint8
type SNIBlotUpType uint8

const (
	SNIBlotUpTypeDefault = iota
	SNIBlotUpTypeOmit
	SNIBlotUpTypeIPAddr
	SNIBlotUpTypeMoniker
)

// semicolon as delimiter of Tags, Proxies
type ServerStamp struct {
	ServerAddrStr string
	ProviderName  string
	Path          string
	Proxies       string //All Ex - proxy
	Tags          string //All Ex + proxy
	SNIShadow     string //DoTEx DOHEx
	SNIBlotUp     SNIBlotUpType //DoTEx DOHEx Proxy
	Props         ServerInformalProperties
	Proto         StampProtoType
	ServerPk      HEXJSON
	Hashes        []HEXJSON
}

func NewServerStampFromString(stampStr string) (ServerStamp, error) {
	if !strings.HasPrefix(stampStr, "sdns:") {
		return ServerStamp{}, errors.New("Stamps are expected to start with sdns:")
	}
	stampStr = stampStr[5:]
	if strings.HasPrefix(stampStr, "//") {
		stampStr = stampStr[2:]
	}
	bin, err := base64.RawURLEncoding.Strict().DecodeString(stampStr)
	if err != nil {
		return ServerStamp{}, err
	}
	if len(bin) < 1 {
		return ServerStamp{}, errors.New("Stamp is too short")
	}
	if bin[0] == uint8(StampProtoTypeDNSCrypt) {
		return newDNSCryptServerStamp(bin, false)
	} else if bin[0] == uint8(StampProtoTypeDoH) {
		return newDoHServerStamp(bin, false)
	} else if bin[0] == uint8(StampProtoTypeDoHEx) {
		return newDoHServerStamp(bin, true)
	} else if bin[0] == uint8(StampProtoTypeDoTEx) {
		return newDoTExServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDNSCryptEx) {
		return newDNSCryptServerStamp(bin, true)
	} else if bin[0] == uint8(StampProtoTypeDNSCryptRelay) {
		return newDNSCryptRelayStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeProxy) {
		return newProxyStamp(bin)
	}
	return ServerStamp{}, errors.New("Unsupported stamp version or protocol")
}

// id(u8)=0x01 props addrLen(1) serverAddr pkStrlen(1) pkStr providerNameLen(1) providerName
func newDNSCryptServerStamp(bin []byte, ex bool) (ServerStamp, error) {
	var stamp ServerStamp
	var err error
	if ex {
		stamp = ServerStamp{Proto: StampProtoTypeDNSCryptEx}
	} else {
		stamp = ServerStamp{Proto: StampProtoTypeDNSCrypt}
	}
	if len(bin) < 66 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
	bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
	if colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(stamp.ServerAddrStr)
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
	}
	if colIndex >= len(stamp.ServerAddrStr)-1 {
		return stamp, errors.New("Invalid stamp (empty port)")
	}
	ipOnly := stamp.ServerAddrStr[:colIndex]
	portOnly := stamp.ServerAddrStr[colIndex+1:]
	if _, err = strconv.ParseUint(portOnly, 10, 16); err != nil {
		return stamp, errors.New("Invalid stamp (port range)")
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return stamp, errors.New("Invalid stamp (IP address)")
	}

	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 2")
	}
	pos++
	stamp.ServerPk = bin[pos : pos+length]
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 3")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	if ex && pos < binLen {
		if _, pos, err = commonExStamp(&stamp, pos, binLen, bin); err != nil {
			return stamp, err
		}
	}

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// id(u8)=0x02 props addrLen(1) serverAddr hashLen(1) hash providerNameLen(1) providerName pathLen(1) path

func newDoHServerStamp(bin []byte, ex bool) (ServerStamp, error) {
	var stamp ServerStamp
	var err error
	if ex {
		stamp = ServerStamp{Proto: StampProtoTypeDoHEx}
	} else {
		stamp = ServerStamp{Proto: StampProtoTypeDoH}
	}
	if len(bin) < 22 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 1")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	for {
		vlen := int(bin[pos])
		length = vlen & ^0x80
		if 1+length >= binLen-pos {
			return stamp, errors.New("Invalid stamp 2")
		}
		pos++
		if length > 0 {
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+length])
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}

	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 3")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 4")
	}
	pos++
	stamp.Path = string(bin[pos : pos+length])
	pos += length
	if ex && pos < binLen {
		stamp.SNIBlotUp = SNIBlotUpType(bin[pos])
		pos++

		length = int(bin[pos])
		if length >= binLen-pos {
			return stamp, errors.New("Invalid stamp 5")
		}
		pos++

		stamp.SNIShadow = string(bin[pos : pos+length])
		pos += length

		if _, pos, err = commonExStamp(&stamp, pos, binLen, bin); err != nil {
			return stamp, err
		}
	}

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if len(stamp.ServerAddrStr) > 0 {
		colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
		bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
		if colIndex < bracketIndex {
			colIndex = -1
		}
		if colIndex < 0 {
			colIndex = len(stamp.ServerAddrStr)
			stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
		}
		if colIndex >= len(stamp.ServerAddrStr)-1 {
			return stamp, errors.New("Invalid stamp (empty port)")
		}
		ipOnly := stamp.ServerAddrStr[:colIndex]
		portOnly := stamp.ServerAddrStr[colIndex+1:]
		if _, err = strconv.ParseUint(portOnly, 10, 16); err != nil {
			return stamp, errors.New("Invalid stamp (port range)")
		}
		if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
			return stamp, errors.New("Invalid stamp (IP address)")
		}
	}

	return stamp, nil
}


func newDoTExServerStamp(bin []byte) (ServerStamp, error) {
	var err error
	stamp := ServerStamp{Proto: StampProtoTypeDoTEx}

	if len(bin) < 21 {
		return stamp, errors.New("Stamp is too short")
	}
	
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 1")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	for {
		vlen := int(bin[pos])
		length = vlen & ^0x80
		if 1+length >= binLen-pos {
			return stamp, errors.New("Invalid stamp 2")
		}
		pos++
		if length > 0 {
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+length])
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}

	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 3")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 4")
	}

	
	stamp.SNIBlotUp = SNIBlotUpType(bin[pos])
	pos++

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 5")
	}
	pos++

	stamp.SNIShadow = string(bin[pos : pos+length])
	pos += length

	if _, pos, err = commonExStamp(&stamp, pos, binLen, bin); err != nil {
		return stamp, err
	}

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if len(stamp.ServerAddrStr) > 0 {
		colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
		bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
		if colIndex < bracketIndex {
			colIndex = -1
		}
		if colIndex < 0 {
			colIndex = len(stamp.ServerAddrStr)
			stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
		}
		if colIndex >= len(stamp.ServerAddrStr)-1 {
			return stamp, errors.New("Invalid stamp (empty port)")
		}
		ipOnly := stamp.ServerAddrStr[:colIndex]
		portOnly := stamp.ServerAddrStr[colIndex+1:]
		if _, err = strconv.ParseUint(portOnly, 10, 16); err != nil {
			return stamp, errors.New("Invalid stamp (port range)")
		}
		if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
			return stamp, errors.New("Invalid stamp (IP address)")
		}
	}
	return stamp, nil
}

func newProxyStamp(bin []byte) (ServerStamp, error) {
	var err error
	stamp := ServerStamp{Proto: StampProtoTypeProxy}

	if len(bin) < 21 {
		return stamp, errors.New("Stamp is too short")
	}
	
	binLen := len(bin)
	pos := 1

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 1")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

//for HTTPS hash digest
	for {
		vlen := int(bin[pos])
		length = vlen & ^0x80
		if 1+length >= binLen-pos {
			return stamp, errors.New("Invalid stamp 2")
		}
		pos++
		if length > 0 {
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+length])
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}

// uri
	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 3")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 4")
	}


	stamp.SNIBlotUp = SNIBlotUpType(bin[pos])
	pos++

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp 5")
	}
	pos++

	stamp.SNIShadow = string(bin[pos : pos+length])
	pos += length

	if _, pos, err = commonExStamp(&stamp, pos, binLen, bin); err != nil {
		return stamp, err
	}

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}

	if len(stamp.ServerAddrStr) > 0 {
		colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
		bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
		if colIndex < bracketIndex {
			colIndex = -1
		}
		if colIndex < 0 {
			colIndex = len(stamp.ServerAddrStr)
			stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
		}
		if colIndex >= len(stamp.ServerAddrStr)-1 {
			return stamp, errors.New("Invalid stamp (empty port)")
		}
		ipOnly := stamp.ServerAddrStr[:colIndex]
		portOnly := stamp.ServerAddrStr[colIndex+1:]
		if _, err := strconv.ParseUint(portOnly, 10, 16); err != nil {
			return stamp, errors.New("Invalid stamp (port range)")
		}
		if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
			return stamp, errors.New("Invalid stamp (IP address)")
		}
	}
	return stamp, nil
}

func commonExStamp(stamp *ServerStamp, pos, binLen int, bin []byte) (*ServerStamp, int, error) {
	var length int
	if pos != binLen {
		length = int(bin[pos])
		if length >= binLen-pos {
			return stamp, pos, errors.New("Invalid stamp Tags")
		}
		pos++
	
		stamp.Tags = string(bin[pos : pos+length])
		pos += length
	}

	if pos != binLen {
		length = int(bin[pos])
		if length >= binLen-pos {
			return stamp, pos, errors.New("Invalid stamp Proxies")
		}
		pos++
	
		stamp.Proxies = string(bin[pos : pos+length])
		pos += length
	}
	return stamp, pos, nil
}


// id(u8)=0x81 addrLen(1) serverAddr

func newDNSCryptRelayStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDNSCryptRelay}
	if len(bin) < 13 {
		return stamp, errors.New("Stamp is too short")
	}
	binLen := len(bin)
	pos := 1
	length := int(bin[pos])
	if 1+length > binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
	bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
	if colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(stamp.ServerAddrStr)
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
	}
	if colIndex >= len(stamp.ServerAddrStr)-1 {
		return stamp, errors.New("Invalid stamp (empty port)")
	}
	ipOnly := stamp.ServerAddrStr[:colIndex]
	portOnly := stamp.ServerAddrStr[colIndex+1:]
	if _, err := strconv.ParseUint(portOnly, 10, 16); err != nil {
		return stamp, errors.New("Invalid stamp (port range)")
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return stamp, errors.New("Invalid stamp (IP address)")
	}
	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}
