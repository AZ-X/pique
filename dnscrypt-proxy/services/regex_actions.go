package services

import (
	"fmt"
	"regexp"
	"strings"
	
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
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
		for j, str := range ent.Exps {
			if len(ent.Exps) == j + 1 {
				fmt.Fprintf(&subs, `(?:%s)`, str)
			} else {
				fmt.Fprintf(&subs, `(?:%s)|`, str)
			}
		}
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
		var sub_rfs strings.Builder
		for i, str := range rfs {
			if len(rfs) == i + 1 {
				fmt.Fprintf(&sub_rfs, `(?:%s)`, str)
			} else {
				fmt.Fprintf(&sub_rfs, `(?:%s)|`, str)
			}
		}
		fmt.Fprintf(&reg, `(?P<RF>(?:%s))`, sub_rfs.String()) 
	}
	if len(nxs) != 0 && (len(ips) != 0 || len(rfs) != 0) {
		fmt.Fprintf(&reg, `|`)
	}
	if len(nxs) != 0 {
		var sub_nxs strings.Builder
		for i, str := range nxs {
			if len(nxs) == i + 1 {
				fmt.Fprintf(&sub_nxs, `(?:%s)`, str)
			} else {
				fmt.Fprintf(&sub_nxs, `(?:%s)|`, str)
			}
		}
		fmt.Fprintf(&reg, `(?P<NX>(?:%s))`, sub_nxs.String())
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

