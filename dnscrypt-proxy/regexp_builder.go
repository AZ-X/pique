package main

import (
	"fmt"
	"regexp"
	"strings"
	
	"github.com/jedisct1/dlog"
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
	dlog.Debugf("regex => %v", reg)
	builder := &regexp_builder{Regexp:regexp.MustCompile(reg.String())}
	return builder
}

