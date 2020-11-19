package channels_test



/*******************************************************

A minimal implementation of dynamic sequence routine

*******************************************************/

import (
	"regexp"
	"testing"
)


func TestOrShowHowReadingBlackCloaking(t *testing.T) {
	return
	var bc = string(`
## YOU CAN DELETE ALL BELOW CONTENT OR KEEP IT AS DEFAULT

# The GAFAM
NX /google /doubleclick /crashlytics /gstatic /firebaseio 
NX /facebook /tfbnw /fbcdn
RF /(wns)|(wdcp)|(wdcpalt)\.windows\.com\.$ # Win32/HostsFileHijack wiki/Criticism_of_Microsoft
RF /1drv\.com\.$ # Win32/HostsFileHijack wiki/Criticism_of_Microsoft

# Criticism of other software companies:
# wiki Criticism of Facebook
# wiki Criticism of Apple
# wiki Criticism of Google
# wiki Criticism of Yahoo!

# github&aws......fruIT&apple......^$^

NX /^ad\..*
NX /^ads\..*
NX /^banner\..*
NX /^banners\..*
NX /^creatives\..*
NX /^oas\..*
NX /^oascentral\..*        # inline comments are allowed after whitespaces and a pound sign
NX /^stats\..*
NX /^tag\..*
NX /^telemetry\..*
NX /^tracker\..*
NX /.*\.local\.$
NX /eth0.\.me\.$
NX /.*\.workgroup\.$
NX /\.in-addr\.arpa\.$

127.0.0.1 localhost
[::1]     localhost

             #comments: whitespace blah-blah-blah
     127.0.0.1 localhost #comments: following blah-blah-blah
 127.0.0.1 /localhost#thisisnotacomment #comments: '/localhost#thisisnotacomment' is considered as a match

# static addresses always work even on 'NX /google'
8.8.8.8                        dns.google.com.
8.8.4.4                        dns.google.com.
[2001:4860:4860::]             dns.google.com.`)
	exp := regexp.MustCompile(`(?m)^(?:[ ]*(?P<target>[\w.:\[\]\%]+)[ ]+(?P<patterns>[^ #\n]{1}[^ \r\n]+(?:[ ]+[^ #\n]{1}[^ \r\n]+)*))?[ ]*(?:[ ]+#(?P<comment>[^\r\n]*))?(?:\r)?$|(?:^[ ]*#(?P<commentline>[^\r\n]*)(?:\r)?$)|(?:^(?P<unrecognized>[^\r\n]*)(?:\r)?$)`)
	exp.Longest()
	whitespaces := regexp.MustCompile(`[ ]+`)
	matches := exp.FindAllStringSubmatch(bc, -1)
	t.Logf("lines in total %d", len(matches))
	for line, match := range matches {
		t.Logf("line=%d, target=%s, patterns=%s, comment=%s, unrecognized=%v",
		line+1,
		match[exp.SubexpIndex("target")],
		whitespaces.Split(match[exp.SubexpIndex("patterns")], -1),
		match[exp.SubexpIndex("comment")] + match[exp.SubexpIndex("commentline")],
		len(match[exp.SubexpIndex("unrecognized")]) != 0 )
	}
}

