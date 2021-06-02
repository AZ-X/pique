package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/AZ-X/pique/repique/behaviors"
	"github.com/AZ-X/pique/repique/features/dns"
	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/configuration"

)

const (
	DefaultTZ = "Local"
	DefaultConfigFileName = "repique.toml"
)

var AppVersion            = "dev-X"

func init() {
	common.AppVersion = AppVersion
}

func main() {
	dlog.Init("repique", dlog.SeverityNotice, "DAEMON")

	flags := &configuration.ConfigFlags{}
	flags.ConfigFile = flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	flags.Check = flag.Bool("check", false, "check the configuration file and exit")
	flags.Child = flag.Bool("child", false, "Invokes program as a child process")

	tz := flag.String("tz", DefaultTZ, "name of time zone")
	off := flag.Int("tzoff", 0, "offset(hours) of time zone")
	version := flag.Bool("version", false, "print current proxy version")
	flag.Parse()
	
	if *version {
		fmt.Println(common.AppVersion)
		os.Exit(0)
	}
	hastz, hastzoff := false, false
	flag.Visit(func (f *flag.Flag) {
		switch f.Name {
			case "tz": 
				hastz = true
				return
			case "tzoff":
				hastzoff = true
				return
		}
	})
	if hastz || hastzoff {
		var loc *time.Location
		var err error
		if hastz {
			loc, err = time.LoadLocation(*tz)
		} else {
			loc = time.FixedZone(DefaultTZ, *off*60*60)
		}
		if err == nil {
			time.Local = loc
		}
	}

	proxy := &dns.Proxy{}
	if err := configuration.ConfigLoad(proxy, flags); err != nil {
		panic(err)
	}
	pid, err := behaviors.NewPidFile()
	if err != nil {
		dlog.Error(err)
	}
	sig := make(chan os.Signal, 10)
	done := make(chan bool, 1)
	signal.Notify(sig, syscall.SIGABRT, syscall.SIGALRM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)
	go func() {
		<-sig
		if pid != nil {
			pid.Remove()
		}
		done <- true
		os.Exit(1)
	}()
	proxy.StartProxy()
	<-done
	dlog.Notice("Quit signal received...")
}
