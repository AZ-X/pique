package nodes

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
)

/* 
	materials hold a simple content view of textual data
	it's easy to review the content or maintain composite mapping between objects
	its format is even tiny for implement(golang std libs) as below
	line 1: identity
	line 2: key1 linecount1
	line 3 .. (2 + linecount1): obj1 obj2 obj3...objN 
	line (3 + linecount1): key2 linecount2
	line (4 + linecount1) .. (3 + linecount1 + linecount2): obj1 obj2 obj3...objN
	.
	.
	.
	line: keyN linecountN
	line: obj1 obj2 obj3...objN
	.....
 */

const (
	eol = "\r\n"
	keyfmt = "%q %d" + eol
	identityfmt = "%x" + eol
)

type marshalable interface {
	material() marshaling
	name() *string
}

// err free
type marshaling interface {
	marshal() *struct{c uint8; v string}
	unmarshal(*struct{c uint8; v string}) *time.Time
}

// err free
type materials struct {
	path              string
	identity          []byte
	values            map[string]*struct{c uint8; v string}  //{key:{linecount,lines}}
}

func (m *materials) open(path string, identity []byte) {
	m.path = path
	m.identity = identity
	m.values = make(map[string]*struct{c uint8; v string})
	if bin, err := os.ReadFile(path); err == nil {
		r := bufio.NewReaderSize(bytes.NewReader(bin), len(bin))
		var identity1 []byte
		if _, err = fmt.Fscanf(r, identityfmt, &identity1); err == nil {
			if bytes.Equal(identity, identity1) {
				var key string
				var count uint8
				KeyLoop: for {
					if _, err = fmt.Fscanf(r, keyfmt, &key, &count); err == nil {
						var lines strings.Builder
						for c := count; c > 0; c-- {
							if b, err := r.ReadBytes('\n'); err == nil {
								lines.Write(b)
								continue
							} else {
								dlog.Debugf("read materials failed: %v", err)
							}
							break KeyLoop
						}
						m.values[key] = &struct{c uint8; v string}{count, lines.String()}
						continue
					} else if err != io.EOF {
						dlog.Debugf("open materials failed: %v", err)
					}
					break
				}
				dlog.Debugf("materials loaded path=%s count=%d", path, len(m.values))
			}
		}
	}
}

func (m *materials) unmarshalto(items []marshalable) (updated []marshalable, dts []*time.Time) {
	for _, item := range items {
		if s, found := m.values[*item.name()]; found {
			if material := item.material(); material != nil {
				if dt := material.unmarshal(s); dt == nil || dt.After(time.Now()) {
					updated = append(updated, item)
					dts = append(dts, dt)
				}
			}
		}
	}
	return
}

func (m *materials) marshalfrom(item marshalable) {
	if material := item.material(); material != nil {
		m.values[*item.name()] = material.marshal()
	}
}

func (m *materials) savepoint() {
	var content strings.Builder
	fmt.Fprintf(&content, identityfmt, m.identity)
	for key, item := range m.values {
		fmt.Fprintf(&content, keyfmt, key, item.c)
		content.WriteString(item.v)
	}
	os.WriteFile(m.path, []byte(content.String()), 0600)
}
