module github.com/AZ-X/dnscrypt-proxy-r2

go 1.14

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/VividCortex/ewma v1.1.1
	github.com/hashicorp/go-immutable-radix v1.2.0
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4
	github.com/jedisct1/dlog v0.0.0-20190909160351-692385b00b84
	github.com/jedisct1/go-clocksmith v0.0.0-20190707124905-73e087c7979c
	github.com/jedisct1/xsecretbox v0.0.0-20190909160646-b731c21297f9
	github.com/k-sone/critbitgo v1.4.0
	github.com/miekg/dns v1.1.29
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	golang.org/x/sys v0.0.0-20200620081246-981b61492c35 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	stammel v0.0.0-00010101000000-000000000000
)

replace github.com/jedisct1/xsecretbox => ../xsecretbox/

replace gopkg.in/natefinch/lumberjack.v2 => ../lumberjack.v2/

replace github.com/jedisct1/dlog => ../dboy/

replace github.com/miekg/dns => ../miekg_dns/

replace stammel => ../stammel/stammel
