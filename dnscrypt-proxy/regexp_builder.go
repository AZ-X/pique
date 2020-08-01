package main

import (
	"fmt"
	"regexp"
	"strings"
)

type regexp_builder struct {
	*regexp.Regexp
}

func CreateRegexBuilder(regexes []string) *regexp_builder {
	var reg strings.Builder
	for i, str := range regexes {
		if len(regexes) == i + 1 {
			fmt.Fprintf(&reg, "(%s)", str)
		} else {
			fmt.Fprintf(&reg, "(%s)|", str)
		}
	}
	builder := &regexp_builder{Regexp:regexp.MustCompile(reg.String())}
	program_dbg_full_log("regex => %s", builder.String())
	return builder
}

