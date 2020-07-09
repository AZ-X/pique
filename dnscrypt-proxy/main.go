package main

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sync"

	"github.com/facebookgo/pidfile"
	"github.com/jedisct1/dlog"
)

const (
	DefaultConfigFileName = "dnscrypt-proxy.toml"
)

var	AppVersion            = "dev-X"
type App struct {
	wg    sync.WaitGroup
	quit  chan struct{}
	proxy *Proxy
	flags *ConfigFlags
}

func main() {
	dlog.Init("dnscrypt-proxy", dlog.SeverityNotice, "DAEMON")

	seed := make([]byte, 8)
	crypto_rand.Read(seed)
	rand.Seed(int64(binary.LittleEndian.Uint64(seed[:])))

	version := flag.Bool("version", false, "print current proxy version")
	flags := ConfigFlags{}
	flags.List = flag.Bool("list", false, "print the list of available resolvers for the enabled filters")
	flags.ListAll = flag.Bool("list-all", false, "print the complete list of available resolvers, ignoring filters")
	flags.JSONOutput = flag.Bool("json", false, "output list as JSON")
	flags.Check = flag.Bool("check", false, "check the configuration file and exit")
	flags.ConfigFile = flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	flags.Child = flag.Bool("child", false, "Invokes program as a child process")
	flags.NetprobeTimeoutOverride = flag.Int("netprobe-timeout", 60, "Override the netprobe timeout")
	flags.ShowCerts = flag.Bool("show-certs", false, "print DoH certificate chain hashes")

	flag.Parse()

	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	app := &App{
		flags: &flags,
	}

	app.proxy = NewProxy()
	app.AppMain()
}


func (app *App) AppMain() {
	if err := ConfigLoad(app.proxy, app.flags); err != nil {
		dlog.Fatal(err)
		os.Exit(1)
	}
	if err := app.proxy.InitPluginsGlobals(); err != nil {
		dlog.Fatal(err)
		os.Exit(1)
	}
	app.quit = make(chan struct{})
	app.wg.Add(1)
	_ = pidfile.Write()
	app.proxy.StartProxy()
	<-app.quit
	dlog.Notice("Quit signal received...")
	app.wg.Done()
}