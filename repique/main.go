package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jedisct1/dlog"
	"github.com/AZ-X/pique/repique/behaviors"
	"github.com/AZ-X/pique/repique/features/dns"
	"github.com/AZ-X/pique/repique/common"
	"github.com/AZ-X/pique/repique/configuration"

)

const (
	DefaultConfigFileName = "repique.toml"
)

var AppVersion            = "dev-X"

func init() {
	common.AppVersion = AppVersion
}

func main() {
	dlog.Init("repique", dlog.SeverityNotice, "DAEMON")

	version := flag.Bool("version", false, "print current proxy version")
	flags := &configuration.ConfigFlags{}
	flags.Check = flag.Bool("check", false, "check the configuration file and exit")
	flags.ConfigFile = flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	flags.Child = flag.Bool("Child", false, "Invokes program as a Child process")

	flag.Parse()

	if *version {
		fmt.Println(common.AppVersion)
		os.Exit(0)
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
