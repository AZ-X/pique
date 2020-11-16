package main

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"

	"github.com/jedisct1/dlog"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/behaviors"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/features/dns"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/common"
	"github.com/AZ-X/dnscrypt-proxy-r2/dnscrypt-proxy/configuration"

)

const (
	DefaultConfigFileName = "dnscrypt-proxy.toml"
)

var AppVersion            = "dev-X"

type App struct {
	proxy *dns.Proxy
	flags *configuration.ConfigFlags
}

func init() {
	common.AppVersion = AppVersion
}

func main() {
	dlog.Init("dnscrypt-proxy", dlog.SeverityNotice, "DAEMON")

	seed := make([]byte, 8)
	crypto_rand.Read(seed)
	rand.Seed(int64(binary.BigEndian.Uint64(seed[:])))

	version := flag.Bool("version", false, "print current proxy version")
	flags := configuration.ConfigFlags{}
	flags.Check = flag.Bool("check", false, "check the configuration file and exit")
	flags.ConfigFile = flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	flags.Child = flag.Bool("Child", false, "Invokes program as a Child process")
	flags.NetprobeTimeoutOverride = flag.Int("netprobe-Timeout", 60, "Override the netprobe Timeout")

	flag.Parse()

	if *version {
		fmt.Println(common.AppVersion)
		os.Exit(0)
	}

	app := &App{
		flags: &flags,
	}

	app.proxy = dns.NewProxy()
	app.AppMain()
}


func (app *App) AppMain() {
	if err := configuration.ConfigLoad(app.proxy, app.flags); err != nil {
		dlog.Fatal(err)
		os.Exit(1)
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
	app.proxy.StartProxy()
	<-done
	dlog.Notice("Quit signal received...")

}