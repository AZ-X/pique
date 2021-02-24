module github.com/AZ-X/pique

go 1.16

require (
	github.com/AZ-X/dns v1.1.39
	github.com/BurntSushi/toml v0.3.1
	github.com/RobinUS2/golang-moving-average v1.0.0
	github.com/jedisct1/dlog v0.0.0-20190909160351-692385b00b84
	github.com/jedisct1/go-clocksmith v0.0.0-20190707124905-73e087c7979c
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	stammel v0.0.0-00010101000000-000000000000
)

replace gopkg.in/natefinch/lumberjack.v2 => ../lumberjack.v2/

replace github.com/jedisct1/dlog => ../dboy/

replace stammel => ../stammel/stammel
