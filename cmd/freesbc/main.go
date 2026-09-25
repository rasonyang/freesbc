// Command freesbc is an all-in-one session border controller:
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
	"syscall"

	"github.com/freesbc/freesbc/internal/app"
)

const usage = `FreeSBC — all-in-one session border controller

Usage:
  freesbc run   [-c sbc.yaml]   start the SBC
  freesbc check [-c sbc.yaml]   validate a config file and exit
`

// version is the build version, overridable via `-ldflags "-X main.version=…"`.
var version = "dev"

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
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("c", "sbc.yaml", "path to config file")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// A positional argument is almost certainly a config path given
	// without -c (`freesbc run edge.yaml`). Ignoring it would run
	// ./sbc.yaml instead — possibly a different, valid config serving the
	// wrong plane — so it is a usage error (audit P2-APP-007).
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "freesbc %s: unexpected argument %q (the config file is given with -c)\n\n%s", cmd, fs.Arg(0), usage)
		return 2
	}

	switch cmd {
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
