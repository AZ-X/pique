module github.com/AZ-X/pique

go 1.22

require (
	github.com/AZ-X/dns v1.1.39
	github.com/BurntSushi/toml v0.3.1
	github.com/RobinUS2/golang-moving-average v1.0.0
	github.com/jedisct1/dlog v0.0.0-20190909160351-692385b00b84
	golang.org/x/crypto v0.17.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace gopkg.in/natefinch/lumberjack.v2 => ./mod/lumberjack.v2

replace github.com/jedisct1/dlog => ./mod/dboy
