package dns

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

const maxTok = 2048 // Largest token we can return.

// The maximum depth of $INCLUDE directives supported by the
// ZoneParser API.
const maxIncludeDepth = 7

// Tokinize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames if they are left blank;
// * Suppress sequences of spaces;
// * Make each RR fit on one line (_NEWLINE is send as last)
// * Handle comments: ;
// * Handle braces - anywhere.
const (
	// Zonefile
	zEOF = iota
	zString
	zBlank
	zQuote
	zNewline
	zRrtpe
	zOwner
	zClass
	zDirOrigin   // $ORIGIN
	zDirTTL      // $TTL
	zDirInclude  // $INCLUDE
	zDirGenerate // $GENERATE

	// Privatekey file
	zValue
	zKey

	zExpectOwnerDir      // Ownername
	zExpectOwnerBl       // Whitespace after the ownername
	zExpectAny           // Expect rrtype, ttl or class
	zExpectAnyNoClass    // Expect rrtype or ttl
	zExpectAnyNoClassBl  // The whitespace after _EXPECT_ANY_NOCLASS
	zExpectAnyNoTTL      // Expect rrtype or class
	zExpectAnyNoTTLBl    // Whitespace after _EXPECT_ANY_NOTTL
	zExpectRrtype        // Expect rrtype
	zExpectRrtypeBl      // Whitespace BEFORE rrtype
	zExpectRdata         // The first element of the rdata
	zExpectDirTTLBl      // Space after directive $TTL
	zExpectDirTTL        // Directive $TTL
	zExpectDirOriginBl   // Space after directive $ORIGIN
	zExpectDirOrigin     // Directive $ORIGIN
	zExpectDirIncludeBl  // Space after directive $INCLUDE
	zExpectDirInclude    // Directive $INCLUDE
	zExpectDirGenerate   // Directive $GENERATE
	zExpectDirGenerateBl // Space after directive $GENERATE
)

// ParseError is a parsing error. It contains the parse error and the location in the io.Reader
// where the error occurred.
type ParseError struct {
	file string
	err  string
	lex  lex
}

func (e *ParseError) Error() (s string) {
	if e.file != "" {
		s = e.file + ": "
	}
	s += "dns: " + e.err + ": " + strconv.QuoteToASCII(e.lex.token) + " at line: " +
		strconv.Itoa(e.lex.line) + ":" + strconv.Itoa(e.lex.column)
	return
}

type lex struct {
	token  string // text of the token
	err    bool   // when true, token text has lexer error
	value  uint8  // value: zString, _BLANK, etc.
	torc   uint16 // type or class as parsed in the lexer, we only need to look this up in the grammar
	line   int    // line in the file
	column int    // column in the file
}

// ttlState describes the state necessary to fill in an omitted RR TTL
type ttlState struct {
	ttl           uint32 // ttl is the current default TTL
	isByDirective bool   // isByDirective indicates whether ttl was set by a $TTL directive
}

type zlexer struct {
	br io.ByteReader

	readErr error

	line   int
	column int

	comBuf  string
	comment string

	l       lex
	cachedL *lex

	brace  int
	quote  bool
	space  bool
	commt  bool
	rrtype bool
	owner  bool

	nextL bool

	eol bool // end-of-line
}

func newZLexer(r io.Reader) *zlexer {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReaderSize(r, 1024)
	}

	return &zlexer{
		br: br,

		line: 1,

		owner: true,
	}
}

func (zl *zlexer) Err() error {
	if zl.readErr == io.EOF {
		return nil
	}

	return zl.readErr
}

// readByte returns the next byte from the input
func (zl *zlexer) readByte() (byte, bool) {
	if zl.readErr != nil {
		return 0, false
	}

	c, err := zl.br.ReadByte()
	if err != nil {
		zl.readErr = err
		return 0, false
	}

	// delay the newline handling until the next token is delivered,
	// fixes off-by-one errors when reporting a parse error.
	if zl.eol {
		zl.line++
		zl.column = 0
		zl.eol = false
	}

	if c == '\n' {
		zl.eol = true
	} else {
		zl.column++
	}

	return c, true
}

func (zl *zlexer) Peek() lex {
	if zl.nextL {
		return zl.l
	}

	l, ok := zl.Next()
	if !ok {
		return l
	}

	if zl.nextL {
		// Cache l. Next returns zl.cachedL then zl.l.
		zl.cachedL = &l
	} else {
		// In this case l == zl.l, so we just tell Next to return zl.l.
		zl.nextL = true
	}

	return l
}

func (zl *zlexer) Next() (lex, bool) {
	l := &zl.l
	switch {
	case zl.cachedL != nil:
		l, zl.cachedL = zl.cachedL, nil
		return *l, true
	case zl.nextL:
		zl.nextL = false
		return *l, true
	case l.err:
		// Parsing errors should be sticky.
		return lex{value: zEOF}, false
	}

	var (
		str [maxTok]byte // Hold string text
		com [maxTok]byte // Hold comment text

		stri int // Offset in str (0 means empty)
		comi int // Offset in com (0 means empty)

		escape bool
	)

	if zl.comBuf != "" {
		comi = copy(com[:], zl.comBuf)
		zl.comBuf = ""
	}

	zl.comment = ""

	for x, ok := zl.readByte(); ok; x, ok = zl.readByte() {
		l.line, l.column = zl.line, zl.column

		if stri >= len(str) {
			l.token = "token length insufficient for parsing"
			l.err = true
			return *l, true
		}
		if comi >= len(com) {
			l.token = "comment length insufficient for parsing"
			l.err = true
			return *l, true
		}

		switch x {
		case ' ', '\t':
			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
			}

			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			var retL lex
			if stri == 0 {
				// Space directly in the beginning, handled in the grammar
			} else if zl.owner {
				// If we have a string and its the first, make it an owner
				l.value = zOwner
				l.token = string(str[:stri])

				// escape $... start with a \ not a $, so this will work
				switch strings.ToUpper(l.token) {
				case "$TTL":
					l.value = zDirTTL
				case "$ORIGIN":
					l.value = zDirOrigin
				case "$INCLUDE":
					l.value = zDirInclude
				case "$GENERATE":
					l.value = zDirGenerate
				}

				retL = *l
			} else {
				l.value = zString
				l.token = string(str[:stri])

				if !zl.rrtype {
					tokenUpper := strings.ToUpper(l.token)
					if t, ok := StringToType[tokenUpper]; ok {
						l.value = zRrtpe
						l.torc = t

						zl.rrtype = true
					} else if strings.HasPrefix(tokenUpper, "TYPE") {
						t, ok := typeToInt(l.token)
						if !ok {
							l.token = "unknown RR type"
							l.err = true
							return *l, true
						}

						l.value = zRrtpe
						l.torc = t

						zl.rrtype = true
					}

					if t, ok := StringToClass[tokenUpper]; ok {
						l.value = zClass
						l.torc = t
					} else if strings.HasPrefix(tokenUpper, "CLASS") {
						t, ok := classToInt(l.token)
						if !ok {
							l.token = "unknown class"
							l.err = true
							return *l, true
						}

						l.value = zClass
						l.torc = t
					}
				}

				retL = *l
			}

			zl.owner = false

			if !zl.space {
				zl.space = true

				l.value = zBlank
				l.token = " "

				if retL == (lex{}) {
					return *l, true
				}

				zl.nextL = true
			}

			if retL != (lex{}) {
				return retL, true
			}
		case ';':
			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
			}

			zl.commt = true
			zl.comBuf = ""

			if comi > 1 {
				// A newline was previously seen inside a comment that
				// was inside braces and we delayed adding it until now.
				com[comi] = ' ' // convert newline to space
				comi++
				if comi >= len(com) {
					l.token = "comment length insufficient for parsing"
					l.err = true
					return *l, true
				}
			}

			com[comi] = ';'
			comi++

			if stri > 0 {
				zl.comBuf = string(com[:comi])

				l.value = zString
				l.token = string(str[:stri])
				return *l, true
			}
		case '\r':
			escape = false

			if zl.quote {
				str[stri] = x
				stri++
			}

			// discard if outside of quotes
		case '\n':
			escape = false

			// Escaped newline
			if zl.quote {
				str[stri] = x
				stri++
				break
			}

			if zl.commt {
				// Reset a comment
				zl.commt = false
				zl.rrtype = false

				// If not in a brace this ends the comment AND the RR
				if zl.brace == 0 {
					zl.owner = true

					l.value = zNewline
					l.token = "\n"
					zl.comment = string(com[:comi])
					return *l, true
				}

				zl.comBuf = string(com[:comi])
				break
			}

			if zl.brace == 0 {
				// If there is previous text, we should output it here
				var retL lex
				if stri != 0 {
					l.value = zString
					l.token = string(str[:stri])

					if !zl.rrtype {
						tokenUpper := strings.ToUpper(l.token)
						if t, ok := StringToType[tokenUpper]; ok {
							zl.rrtype = true

							l.value = zRrtpe
							l.torc = t
						}
					}

					retL = *l
				}

				l.value = zNewline
				l.token = "\n"

				zl.comment = zl.comBuf
				zl.comBuf = ""
				zl.rrtype = false
				zl.owner = true

				if retL != (lex{}) {
					zl.nextL = true
					return retL, true
				}

				return *l, true
			}
		case '\\':
			// comments do not get escaped chars, everything is copied
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			// something already escaped must be in string
			if escape {
				str[stri] = x
				stri++

				escape = false
				break
			}

			// something escaped outside of string gets added to string
			str[stri] = x
			stri++

			escape = true
		case '"':
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			if escape {
				str[stri] = x
				stri++

				escape = false
				break
			}

			zl.space = false

			// send previous gathered text and the quote
			var retL lex
			if stri != 0 {
				l.value = zString
				l.token = string(str[:stri])

				retL = *l
			}

			// send quote itself as separate token
			l.value = zQuote
			l.token = "\""

			zl.quote = !zl.quote

			if retL != (lex{}) {
				zl.nextL = true
				return retL, true
			}

			return *l, true
		case '(', ')':
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
			}

			switch x {
			case ')':
				zl.brace--

				if zl.brace < 0 {
					l.token = "extra closing brace"
					l.err = true
					return *l, true
				}
			case '(':
				zl.brace++
			}
		default:
			escape = false

			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			str[stri] = x
			stri++

			zl.space = false
		}
	}

	if zl.readErr != nil && zl.readErr != io.EOF {
		// Don't return any tokens after a read error occurs.
		return lex{value: zEOF}, false
	}

	var retL lex
	if stri > 0 {
		// Send remainder of str
		l.value = zString
		l.token = string(str[:stri])
		retL = *l

		if comi <= 0 {
			return retL, true
		}
	}

	if comi > 0 {
		// Send remainder of com
		l.value = zNewline
		l.token = "\n"
		zl.comment = string(com[:comi])

		if retL != (lex{}) {
			zl.nextL = true
			return retL, true
		}

		return *l, true
	}

	if zl.brace != 0 {
		l.token = "unbalanced brace"
		l.err = true
		return *l, true
	}

	return lex{value: zEOF}, false
}

func (zl *zlexer) Comment() string {
	if zl.l.err {
		return ""
	}

	return zl.comment
}

// Extract the class number from CLASSxx
func classToInt(token string) (uint16, bool) {
	offset := 5
	if len(token) < offset+1 {
		return 0, false
	}
	class, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(class), true
}

// Extract the rr number from TYPExxx
func typeToInt(token string) (uint16, bool) {
	offset := 4
	if len(token) < offset+1 {
		return 0, false
	}
	typ, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(typ), true
}
