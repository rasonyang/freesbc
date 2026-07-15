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

	"github.com/freesbc/freesbc/config"
)

const usage = `FreeSBC — all-in-one session border controller

Usage:
  freesbc run   [-c sbc.yaml]   start the SBC
  freesbc check [-c sbc.yaml]   validate a config file and exit
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("c", "sbc.yaml", "path to config file")
	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "check":
		if _, err := config.Load(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "config invalid:\n%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s: config OK\n", *cfgPath)
	case "run":
		if err := run(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "freesbc: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func run(cfgPath string) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	store := config.NewStore(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := config.Watch(ctx, cfgPath, store, log); err != nil && ctx.Err() == nil {
			log.Error("config watcher exited", "err", err)
		}
	}()

	log.Info("freesbc started",
		"config", cfgPath,
		"peers", len(store.Current().Peers),
		"routes", len(store.Current().Routes))

	// M2+: media port pool, SIP listeners, shield, and admin API start here,
	// each reading snapshots via store.Current().

	<-ctx.Done()
	log.Info("shutting down")
	return nil
}
