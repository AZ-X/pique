module github.com/AZ-X/pique

go 1.15

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/RobinUS2/golang-moving-average v1.0.0
	github.com/jedisct1/dlog v0.0.0-20190909160351-692385b00b84
	github.com/jedisct1/go-clocksmith v0.0.0-20190707124905-73e087c7979c
	github.com/miekg/dns v1.1.35
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	stammel v0.0.0-00010101000000-000000000000
)

replace gopkg.in/natefinch/lumberjack.v2 => ../lumberjack.v2/

replace github.com/jedisct1/dlog => ../dboy/

replace github.com/miekg/dns => ../miekg_dns/

replace stammel => ../stammel/stammel
