package services

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/AZ-X/pique/repique/common"
)

type Regex_Actions struct {
	*regexp.Regexp
	Refused               int
	NXDOMAIN              int
	Anycast               map[int]interface{}
}

// ips-dms|rfs|nxs -lpcre???
func CreateRegexActions(rfs []string, nxs []string, anycast []struct{Tag interface{};Exps []string}) *Regex_Actions {
	var reg strings.Builder
	var anycastNames = make(map[*string]interface{})
	fmt.Fprintf(&reg, `(?i)`)
	for i, ent := range anycast {
		name := fmt.Sprintf(`Tag%d`, i+1)
		anycastNames[&name] = ent.Tag
		var subs strings.Builder
		fmt.Fprintf(&subs, `(?:%s)`, strings.Join(ent.Exps, reg_delimiter))
		if len(anycast) == i + 1 {
			fmt.Fprintf(&reg, `(?P<%s>(?:%s))`, name, subs.String())
		} else {
			fmt.Fprintf(&reg, `(?P<%s>(?:%s))|`, name, subs.String())
		}
	}
	if len(anycast) != 0 && len(rfs) != 0 {
		fmt.Fprintf(&reg, `|`)
	}
	if len(rfs) != 0 {
		fmt.Fprintf(&reg, `(?P<RF>(?:(?:%s)))`, strings.Join(rfs, reg_delimiter)) 
	}
	if len(nxs) != 0 && (len(anycast) != 0 || len(rfs) != 0) {
		fmt.Fprintf(&reg, `|`)
	}
	if len(nxs) != 0 {
		fmt.Fprintf(&reg, `(?P<NX>(?:(?:%s)))`, strings.Join(nxs, reg_delimiter))
	}
	actions := &Regex_Actions{Regexp:regexp.MustCompile(reg.String())}
	actions.Refused = actions.SubexpIndex("RF")
	actions.NXDOMAIN = actions.SubexpIndex("NX")
	actions.Anycast = make(map[int]interface{})
	for k, v := range anycastNames {
		actions.Anycast[actions.SubexpIndex(*k)] = v
	}
	common.Program_dbg_full_log("regex => %s", actions.String())
	return actions
}

