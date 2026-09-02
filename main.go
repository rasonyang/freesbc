// Command freesbc is an all-in-one session border controller:
// one binary, one YAML file, `freesbc run`.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/freesbc/freesbc/admin"
	"github.com/freesbc/freesbc/callstate"
	"github.com/freesbc/freesbc/config"
	"github.com/freesbc/freesbc/media"
	"github.com/freesbc/freesbc/proxy"
	"github.com/freesbc/freesbc/sig"
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

	// The trunk B2BUA plane runs only when there are trunks to serve. A
	// proxy-only deployment configures no peers and no listen.sip, and
	// starting the trunk listeners there would bind ports nothing uses.
	// Validation guarantees the two go together: a trunk listener with no
	// peers is rejected at load time, so "no peers" really does mean "no
	// trunk plane" rather than a silently dead listener.
	var sipServer *sig.Server
	if len(store.Current().Peers) > 0 {
		sipServer = sig.NewServer(store, pool, log)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sipServer.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("sip server exited", "err", err)
				stop() // a fatal bind error tears the whole process down
			}
		}()
	}

	// The edge proxy plane: public SIP/UDP + WS/WSS toward phones and
	// browsers, one upstream FreeSWITCH, media anchored through the SBC.
	// Entirely independent of the trunk plane above — its own user agent,
	// listeners and media pools — so either may run alone or both together.
	var edge *proxy.Server
	if store.Current().ProxyEnabled() {
		edge, err = proxy.New(store, log)
		if err != nil {
			return fmt.Errorf("edge proxy: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := edge.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("edge proxy exited", "err", err)
				stop()
			}
		}()
	}
	if sipServer == nil && edge == nil {
		return fmt.Errorf("nothing to run: configure trunk peers, sip.upstream.address, or both")
	}

	// The B2BUA bridge (M3.3) is wired into sipServer above (sig.NewServer /
	// sig.Server.Run). Only the shield (M6) and admin API (M7) still attach
	// here.

	if adminCfg := store.Current().Admin; adminCfg != nil {
		deps := adminDeps(store, pool, sipServer, edge)
		adminSrv := admin.New(adminCfg, store, deps, log, cfgPath)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := adminSrv.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("admin server exited", "err", err)
				stop() // fatal bind error tears the process down (like the SIP listener)
			}
		}()
	}

	log.Info("freesbc started",
		"config", cfgPath,
		"peers", len(store.Current().Peers),
		"routes", len(store.Current().Routes))

	<-ctx.Done()
	log.Info("shutting down")
	wg.Wait()
	return nil
}

// adminDeps assembles the admin API's view of whichever planes are
// running. Either plane may be absent (a proxy-only or trunk-only
// deployment), so every accessor is nil-guarded rather than assuming both.
func adminDeps(store *config.Store, pool *media.Pool, sipServer *sig.Server, edge *proxy.Server) admin.Deps {
	deps := admin.Deps{
		Ports:   pool.Stats,
		Version: version,
		Calls:   func() []callstate.Call { return nil },
		ActiveCalls: func() int {
			n := 0
			if sipServer != nil {
				n += sipServer.ActiveCalls()
			}
			if edge != nil {
				n += edge.ActiveCalls()
			}
			return n
		},
		KillCall: func(string) bool { return false },
		Unban:    func(string) bool { return false },
		Shield:   func() admin.ShieldStats { return admin.ShieldStats{DropsByReason: map[string]int64{}} },
		Peers:    func() []admin.PeerStatus { return nil },
	}
	if sipServer != nil {
		deps.Calls = sipServer.Calls
		deps.KillCall = sipServer.KillCall
		deps.Unban = func(ip string) bool {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return false
			}
			return sipServer.Unban(addr)
		}
		deps.Shield = func() admin.ShieldStats {
			st := sipServer.ShieldStats()
			return admin.ShieldStats{BannedCurrent: st.BannedCurrent, BanAddsRejected: st.BanAddsRejected, DropsByReason: st.DropsByReason}
		}
		deps.Peers = func() []admin.PeerStatus {
			cfg := store.Current()
			out := make([]admin.PeerStatus, 0, len(cfg.Peers))
			for name, p := range cfg.Peers {
				out = append(out, admin.PeerStatus{
					Name: name, Address: p.Address, Transport: p.Transport, SRTP: p.SRTP,
					Register: p.Register, Registered: sipServer.IsRegistered(name),
				})
			}
			return out
		}
	}
	if edge != nil {
		deps.Proxy = func() admin.ProxyStats {
			s := edge.Metrics().Snapshot()
			return admin.ProxyStats{
				ActiveRegistrations:    s.ActiveRegistrations,
				ActiveDialogs:          s.ActiveDialogs,
				ActiveMediaSessions:    s.ActiveMediaSessions,
				ActiveWebRTCSessions:   s.ActiveWebRTCSessions,
				RegistrationTotal:      s.RegistrationTotal,
				RegistrationFailure:    s.RegistrationFailure,
				RequestsIn:             s.RequestsIn,
				ResponsesOut:           s.ResponsesOut,
				RTPPacketsRx:           s.RTPPacketsRx,
				RTPPacketsTx:           s.RTPPacketsTx,
				RTPBytesRx:             s.RTPBytesRx,
				RTPBytesTx:             s.RTPBytesTx,
				PortAllocationFailures: s.MediaPortAllocationFailures,
				ICEFailures:            s.WebRTCICEFailures,
				DTLSFailures:           s.WebRTCDTLSFailures,
			}
		}
	}
	return deps
}
