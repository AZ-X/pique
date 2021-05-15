package configuration

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	
	"github.com/AZ-X/pique/repique/common"
	"github.com/jedisct1/dlog"
	"github.com/AZ-X/pique/repique/unclassified/stammel"
)


/* 
		DO NOT REWRITE IT, 
		IT'S BORING 
 */

/* DO NOT DELETE IT, IT'S FUN */
const (
	DefaultPrefetchDelay    time.Duration = 24 * time.Hour
	MinimumPrefetchInterval time.Duration = 6 * time.Hour
)


type Source struct {
	name                    string
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

func (source *Source) ReadFile(now time.Time, hasher hash.Hash) (delay time.Duration, err error, in []byte) {
	var bin, sig []byte
	if bin, err = os.ReadFile(source.cacheFile); err != nil {
		return
	}
	io.Copy(hasher, bytes.NewReader(bin))
	if sig, err = os.ReadFile(source.cacheFile + ".minisig"); err != nil {
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
		dlog.Debugf("joking^^: file [%s] is still fresh, next juicy update: %v", source.cacheFile, delay)
	} else {
		dlog.Debugf("file [%s] needs to be rebuilt by yourself", source.cacheFile)
	}
	return
}

//isolated obsolete
func fetchFromURL(u *url.URL) (bin []byte, err error) {
	return nil, errors.New("not supported yet") //  yes won't support idiocy forever
}

// NewSource loads a new source using the given cacheFile and urls, ensuring it has a valid signature
func NewSource(name string, urls []string, minisignKeyStr string, cacheFile string, refreshDelay time.Duration) (source *Source, err error) {
	if refreshDelay < DefaultPrefetchDelay {
		refreshDelay = DefaultPrefetchDelay
	}
	source = &Source{name: name, cacheFile: cacheFile, cacheTTL: refreshDelay, prefetchDelay: DefaultPrefetchDelay}
	if minisignKey, err := stammel.NewPublicKey(minisignKeyStr); err == nil {
		source.minisignKey = &minisignKey
	}
	return
}

func (source *Source) Parse(prefix string, hasher hash.Hash) ([]*common.RegisteredServer, error) {
	var RegisteredServers []*common.RegisteredServer
	var stampErrs []string
	appendStampErr := func(format string, a ...interface{}) {
		stampErr := fmt.Sprintf(format, a...)
		stampErrs = append(stampErrs, stampErr)
		dlog.Warn(stampErr)
	}
	_, err , source_in := source.ReadFile(time.Now(), hasher)
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
					appendStampErr("multiple stamps for server [%s]", name)
					continue PartsLoop
				}
				stampStr = subpart
				continue
			} else if len(subpart) == 0 || strings.HasPrefix(subpart, "//") {
				continue
			}
		}
		if len(stampStr) < 6 {
			appendStampErr("missing stamp for server [%s]", name)
			continue
		}
		stamp, err := stammel.NewServerStampFromString(stampStr)
		if err != nil {
			appendStampErr("invalid or unsupported stamp [%v]: %s", stampStr, err.Error())
			continue
		}
		registeredServer := &common.RegisteredServer{Name: name, Stamp: &stamp,}
		RegisteredServers = append(RegisteredServers, registeredServer)
	}
	if len(stampErrs) > 0 {
		return RegisteredServers, dlog.Errorf("%s", strings.Join(stampErrs, ", "))
	}
	return RegisteredServers, nil
}
