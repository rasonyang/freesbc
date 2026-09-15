// Command freesbc is an all-in-one session border controller:
// one binary, one YAML file, `freesbc run`.
package main

import (
	"context"
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
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("c", "sbc.yaml", "path to config file")
	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "check":
		if err := app.Check(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s: config OK\n", *cfgPath)
	case "run":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		opts := app.Options{
			ConfigPath: *cfgPath,
			Log:        slog.New(slog.NewTextHandler(os.Stderr, nil)),
			Version:    version,
		}
		if err := app.Run(ctx, opts); err != nil {
			fmt.Fprintf(os.Stderr, "freesbc: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}
