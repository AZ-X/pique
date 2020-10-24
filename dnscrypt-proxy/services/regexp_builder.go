package services

import (
	"fmt"
	"regexp"
	"strings"
	
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
)

type Regexp_builder struct {
	*regexp.Regexp
}

func CreateRegexBuilder(regexes []string, groups []string) *Regexp_builder {
	var reg strings.Builder
	g := len(groups) > 0
	if g && len(regexes) != len (groups) {
		panic("length of groups should equal to regexes")
	}
	for i, str := range regexes {
		if len(regexes) == i + 1 {
			if g {
				fmt.Fprintf(&reg, "(?P<%s>%s)", groups[i], str)
			} else {
				fmt.Fprintf(&reg, "(%s)", str)
			}
		} else {
			if g {
				fmt.Fprintf(&reg, "(?P<%s>%s)|", groups[i], str)
			} else {
				fmt.Fprintf(&reg, "(%s)|", str)
			}
		}
	}
	builder := &Regexp_builder{Regexp:regexp.MustCompile(reg.String())}
	common.Program_dbg_full_log("regex => %s", builder.String())
	return builder
}
