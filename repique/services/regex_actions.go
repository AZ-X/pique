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
	IPAddress             map[int]*common.Endpoint
}

// ips|rfs|nxs -lpcre???
func CreateRegexActions(rfs []string, nxs []string, ips []struct{*common.Endpoint;Exps []string}) *Regex_Actions {
	var reg strings.Builder
	var ipNames = make(map[*string]*common.Endpoint)
	fmt.Fprintf(&reg, `(?i)`)
	for i, ent := range ips {
		name := fmt.Sprintf(`IP%d`, i+1)
		ipNames[&name] = ent.Endpoint
		var subs strings.Builder
		fmt.Fprintf(&subs, `(?:%s)`, strings.Join(ent.Exps, reg_delimiter))
		if len(ips) == i + 1 {
			fmt.Fprintf(&reg, `(?P<%s>(?:%s))`, name, subs.String())
		} else {
			fmt.Fprintf(&reg, `(?P<%s>(?:%s))|`, name, subs.String())
		}
	}
	if len(ips) != 0 && len(rfs) != 0 {
		fmt.Fprintf(&reg, `|`)
	}
	if len(rfs) != 0 {
		fmt.Fprintf(&reg, `(?P<RF>(?:(?:%s)))`, strings.Join(rfs, reg_delimiter)) 
	}
	if len(nxs) != 0 && (len(ips) != 0 || len(rfs) != 0) {
		fmt.Fprintf(&reg, `|`)
	}
	if len(nxs) != 0 {
		fmt.Fprintf(&reg, `(?P<NX>(?:(?:%s)))`, strings.Join(nxs, reg_delimiter))
	}
	actions := &Regex_Actions{Regexp:regexp.MustCompile(reg.String())}
	actions.Refused = actions.SubexpIndex("RF")
	actions.NXDOMAIN = actions.SubexpIndex("NX")
	actions.IPAddress = make(map[int]*common.Endpoint)
	for k, v := range ipNames {
		actions.IPAddress[actions.SubexpIndex(*k)] = v
	}
	common.Program_dbg_full_log("regex => %s", actions.String())
	return actions
}

