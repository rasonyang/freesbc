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
	"sync"
	"syscall"

	"github.com/freesbc/freesbc/config"
	"github.com/freesbc/freesbc/media"
	"github.com/freesbc/freesbc/sig"
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
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("c", "sbc.yaml", "path to config file")
	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "check":
		if _, err := config.Load(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
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

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := config.Watch(ctx, cfgPath, store, log); err != nil && ctx.Err() == nil {
			log.Error("config watcher exited", "err", err)
		}
	}()

	pool := media.NewPool(store)

	mediaCfg := store.Current().Listen.Media
	log.Info("media plane ready",
		"port_range", fmt.Sprintf("%d-%d", mediaCfg.PortRange.Min, mediaCfg.PortRange.Max),
		"rtp_timeout", mediaCfg.RTPTimeout.Std())

	sipServer := sig.NewServer(store, pool, log)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sipServer.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("sip server exited", "err", err)
			stop() // a fatal bind error tears the whole process down
		}
	}()

	// The B2BUA bridge (M3.3) is wired into sipServer above (sig.NewServer /
	// sig.Server.Run). Only the shield (M6) and admin API (M7) still attach
	// here.

	log.Info("freesbc started",
		"config", cfgPath,
		"peers", len(store.Current().Peers),
		"routes", len(store.Current().Routes))

	<-ctx.Done()
	log.Info("shutting down")
	wg.Wait()
	return nil
}
