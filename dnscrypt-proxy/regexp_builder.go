package main

import (
	"fmt"
	"regexp"
	"strings"
)

type regexp_builder struct {
	*regexp.Regexp
}

func CreateRegexBuilder(regexes []string, groups []string) *regexp_builder {
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
	builder := &regexp_builder{Regexp:regexp.MustCompile(reg.String())}
	program_dbg_full_log("regex => %s", builder.String())
	return builder
}

