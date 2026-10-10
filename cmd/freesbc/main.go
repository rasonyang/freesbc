// Command freesbc is an edge session border controller:
// one binary, one YAML file, `freesbc run`.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/term"

	"github.com/freesbc/freesbc/internal/app"
)

const usage = `FreeSBC — SIP/WebRTC edge session border controller

Usage:
  freesbc run   [-c freesbc.yaml]   start the SBC
  freesbc check [-c freesbc.yaml]   validate a config file and exit
  freesbc init  [-c freesbc.yaml]   write a minimal config with detected addresses
        [--switch IP[:port]] [--private-ip IP] [--public-ip IP] [--public-bind IP]
        [--udp-port N] [--no-public-lookup]   (env: FREESBC_SWITCH, FREESBC_PRIVATE_IP,
        FREESBC_PUBLIC_IP, FREESBC_PUBLIC_BIND, FREESBC_UDP_PORT)
  freesbc version                   print the version and exit
`

// version is the build version, overridable via `-ldflags "-X main.version=…"`.
var version = "dev"

// versionLine is the one line `freesbc version` prints: the build version,
// the Go toolchain that built it and the target platform.
func versionLine() string {
	return fmt.Sprintf("freesbc %s %s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is main without the process exit, so the argument handling can be
// tested: it returns the exit code.
func run(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	cmd := args[0]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return 0
	}
	// version takes neither flags nor arguments, so it is handled before
	// flag parsing: `freesbc version -c x` is a usage error, not a config path.
	if cmd == "version" {
		if len(args) > 1 {
			fmt.Fprintf(os.Stderr, "freesbc version: unexpected argument %q (version takes no arguments)\n\n%s", args[1], usage)
			return 2
		}
		fmt.Println(versionLine())
		return 0
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("c", "freesbc.yaml", "path to config file")
	var initOpts app.InitOptions
	var udpPort string
	if cmd == "init" {
		fs.StringVar(&initOpts.Switch, "switch", os.Getenv("FREESBC_SWITCH"), "switch address, IP[:port]")
		fs.StringVar(&initOpts.PrivateIP, "private-ip", os.Getenv("FREESBC_PRIVATE_IP"), "private.ip (default: detected)")
		fs.StringVar(&initOpts.PublicIP, "public-ip", os.Getenv("FREESBC_PUBLIC_IP"), "public.ip (default: looked up)")
		fs.StringVar(&initOpts.PublicBind, "public-bind", os.Getenv("FREESBC_PUBLIC_BIND"), "public.bind (default: detected)")
		fs.StringVar(&udpPort, "udp-port", os.Getenv("FREESBC_UDP_PORT"), "edge.listen.udp (default 5060)")
		fs.BoolVar(&initOpts.NoPublicLookup, "no-public-lookup", false, "do not ask a public service for public.ip")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// A positional argument is almost certainly a config path given
	// without -c (`freesbc run other.yaml`). Ignoring it would run
	// ./freesbc.yaml instead — possibly a different, valid config serving the
	// wrong plane — so it is a usage error (audit P2-APP-007).
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "freesbc %s: unexpected argument %q (the config file is given with -c)\n\n%s", cmd, fs.Arg(0), usage)
		return 2
	}

	switch cmd {
	case "init":
		if udpPort != "" {
			n, err := strconv.Atoi(udpPort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "freesbc init: --udp-port %q is not a number\n", udpPort)
				return 2
			}
			initOpts.UDPPort = n
		}
		fd := int(os.Stdin.Fd())
		initOpts.Path = *cfgPath
		initOpts.Interactive = term.IsTerminal(fd)
		initOpts.In = os.Stdin
		initOpts.Out = os.Stdout
		initOpts.Err = os.Stderr
		initOpts.ReadPassword = func() (string, error) {
			b, err := term.ReadPassword(fd)
			return string(b), err
		}
		initOpts.PrivateIPToward = app.PrivateIPToward
		initOpts.DefaultRouteIP = app.DefaultRouteIP
		initOpts.LookupPublicIP = app.LookupPublicIP
		if err := app.Init(context.Background(), initOpts); err != nil {
			fmt.Fprintf(os.Stderr, "freesbc: %v\n", err)
			return 1
		}
		return 0
	case "check":
		if err := app.Check(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		fmt.Printf("%s: config OK\n", *cfgPath)
		return 0
	case "run":
		opts := app.Options{
			ConfigPath: *cfgPath,
			Log:        slog.New(slog.NewTextHandler(os.Stderr, nil)),
			Version:    version,
		}
		err := withSignals(func(ctx context.Context) error { return app.Run(ctx, opts) })
		if err != nil {
			fmt.Fprintf(os.Stderr, "freesbc: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
}

// withSignals runs fn under a context cancelled by the first SIGINT or
// SIGTERM, which starts a graceful shutdown. Signal capture is released
// the moment that happens, so a second signal gets Go's default action and
// ends the process even when the shutdown hangs (audit P2-APP-008).
func withSignals(fn func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	return fn(ctx)
}
