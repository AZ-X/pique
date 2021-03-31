package configuration

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	
	"github.com/AZ-X/pique/repique/protocols/tls"
	"github.com/AZ-X/pique/repique/common"
	"github.com/jedisct1/dlog"
	"github.com/AZ-X/pique/repique/unclassified/stammel"
)

type SourceFormat int

const (
	SourceFormatV2 = iota
)

const (
	DefaultPrefetchDelay    time.Duration = 24 * time.Hour
	MinimumPrefetchInterval time.Duration = 6 * time.Hour
)

type Source struct {
	name                    string
	format                  SourceFormat
	minisignKey             *stammel.PublicKey
	cacheFile               string
	cacheTTL, prefetchDelay time.Duration
	refresh                 time.Time
}

func (source *Source) checkSignature(bin, sig []byte) (err error) {
	var signature stammel.Signature
	if signature, err = stammel.DecodeSignature(string(sig)); err == nil {
		_, err = source.minisignKey.Verify(bin, signature)
	}
	return
}

// timeNow can be replaced by tests to provide a static value
var timeNow = time.Now

func (source *Source) fetchFromCache(now time.Time) (delay time.Duration, err error, in []byte) {
	var bin, sig []byte
	if bin, err = ioutil.ReadFile(source.cacheFile); err != nil {
		return
	}
	if sig, err = ioutil.ReadFile(source.cacheFile + ".minisig"); err != nil {
		return
	}
	if err = source.checkSignature(bin, sig); err != nil {
		return
	}
	in = bin
	var fi os.FileInfo
	if fi, err = os.Stat(source.cacheFile); err != nil {
		return
	}
	if elapsed := now.Sub(fi.ModTime()); elapsed < source.cacheTTL {
		delay = source.prefetchDelay - elapsed
		dlog.Debugf("joking^^ source [%s] Cache file [%s] is still fresh, next update: %v", source.name, source.cacheFile, delay)
	} else {
		dlog.Debugf("source [%s] Cache file [%s] needs to be refreshed", source.name, source.cacheFile)
	}
	return
}

// if the whole process can NOT boost itself using secure dns query, why leave it here? for an infinite loop by system resolver?
func fetchFromURL(XTransport *tls.XTransport, u *url.URL) (bin []byte, err error) {
	return nil, errors.New("Not supported yet")
}

// NewSource loads a new source using the given cacheFile and urls, ensuring it has a valid signature
func NewSource(name string, XTransport *tls.XTransport, urls []string, minisignKeyStr string, cacheFile string, formatStr string, refreshDelay time.Duration) (source *Source, err error) {
	if refreshDelay < DefaultPrefetchDelay {
		refreshDelay = DefaultPrefetchDelay
	}
	source = &Source{name: name, cacheFile: cacheFile, cacheTTL: refreshDelay, prefetchDelay: DefaultPrefetchDelay}
	if formatStr == "v2" {
		source.format = SourceFormatV2
	} else {
		return source, dlog.Errorf("Unsupported source format: [%s]", formatStr)
	}
	if minisignKey, err := stammel.NewPublicKey(minisignKeyStr); err == nil {
		source.minisignKey = &minisignKey
	}
	return
}

func (source *Source) Parse(prefix string) ([]common.RegisteredServer, error) {
	if source.format == SourceFormatV2 {
		return source.parseV2to3(prefix)
	}
	panic("unexpected source format")
	return []common.RegisteredServer{}, nil
}

func (source *Source) parseV2to3(prefix string) ([]common.RegisteredServer, error) {
	var RegisteredServers []common.RegisteredServer
	var stampErrs []string
	appendStampErr := func(format string, a ...interface{}) {
		stampErr := fmt.Sprintf(format, a...)
		stampErrs = append(stampErrs, stampErr)
		dlog.Warn(stampErr)
	}
	_, err , source_in := source.fetchFromCache(timeNow())
	if err != nil {
		return nil, err
	}
	in := string(source_in)
	parts := strings.Split(in, "## ")
	if len(parts) < 2 {
		return RegisteredServers, dlog.Errorf("Invalid format for source [%s]", source.name)
	}
	parts = parts[1:]
PartsLoop:
	for _, part := range parts {
		part = strings.TrimFunc(part, unicode.IsSpace)
		subparts := strings.Split(part, "\n")
		if len(subparts) < 2 {
			return RegisteredServers, dlog.Errorf("Invalid format for source at [%s]", source.name)
		}
		name := strings.TrimFunc(subparts[0], unicode.IsSpace)
		if len(name) == 0 {
			return RegisteredServers, dlog.Errorf("Invalid format for source at [%s]", source.name)
		}
		subparts = subparts[1:]
		name = prefix + name
		var stampStr string
		for _, subpart := range subparts {
			subpart = strings.TrimFunc(subpart, unicode.IsSpace)
			if strings.HasPrefix(subpart, "sdns:") {
				if len(stampStr) > 0 {
					appendStampErr("Multiple stamps for server [%s]", name)
					continue PartsLoop
				}
				stampStr = subpart
				continue
			} else if len(subpart) == 0 || strings.HasPrefix(subpart, "//") {
				continue
			}
		}
		if len(stampStr) < 6 {
			appendStampErr("Missing stamp for server [%s]", name)
			continue
		}
		stamp, err := stammel.NewServerStampFromString(stampStr)
		if err != nil {
			appendStampErr("Invalid or unsupported stamp [%v]: %s", stampStr, err.Error())
			continue
		}
		registeredServer := common.RegisteredServer{Name: name, Stamp: &stamp,}
		dlog.Debugf("registered [%s] with stamp [%s]", name, stampStr)
		RegisteredServers = append(RegisteredServers, registeredServer)
	}
	if len(stampErrs) > 0 {
		return RegisteredServers, dlog.Errorf("%s", strings.Join(stampErrs, ", "))
	}
	return RegisteredServers, nil
}
