// Package app owns construction and lifecycle: it turns a config file path
// into a running set of components (config watcher, edge,
// admin HTTP surface) and runs them until the context is
// cancelled or one of them fails. cmd/freesbc does argv parsing and exit
// codes; everything else lives here.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/freesbc/freesbc/internal/admin"
	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/edge"
)

// Options are Run's inputs. Log and Version are optional; ConfigPath is not.
type Options struct {
	ConfigPath string
	Log        *slog.Logger
	Version    string
}

// Check validates a config file without starting anything.
func Check(path string) error {
	_, err := config.Load(path)
	return err
}

// Run loads the config, starts every configured component and blocks until
// ctx is cancelled or the first component fails. The first error cancels the
// rest and is what Run returns; a clean shutdown (ctx cancelled) returns nil.
//
// Run takes a plain context and installs no signal handlers of its own, so a
// test can drive it with context.WithCancel. Signal handling belongs to the
// caller (cmd/freesbc).
func Run(ctx context.Context, opts Options) error {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(nopWriter{}, nil))
	}

	// cfg is the startup snapshot. Every startup decision below reads it,
	// never store.Current(): the watcher starts part-way through, and a
	// reload landing then must not give one startup two configurations
	// (audit P2-APP-004).
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	store := config.NewStore(cfg)

	// The edge: public SIP/UDP + WS/WSS toward phones, browsers and
	// carriers, the switch behind it, media anchored through the SBC.
	edgeSrv, err := edge.New(store, log, testHookEdgeOptions...)
	if err != nil {
		return fmt.Errorf("edge: %w", err)
	}
	log.Info("media planes ready", "rtp", fmt.Sprintf("%d-%d", cfg.RTP.Min, cfg.RTP.Max),
		"public_bind", cfg.PublicBind().String(), "private", cfg.PrivateIP().String())

	// One errgroup for every long-running component: the first non-nil
	// error cancels the shared context, which is how a fatal bind error in
	// any one listener tears the whole process down.
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := config.Watch(gctx, opts.ConfigPath, store, log); err != nil && gctx.Err() == nil {
			log.Error("config watcher exited", "err", err)
		}
		// A dead watcher costs reloads, not calls: never fatal.
		return nil
	})
	if testHookWatchStarted != nil {
		testHookWatchStarted(store)
	}

	g.Go(func() error {
		if err := edgeSrv.Run(gctx); err != nil && gctx.Err() == nil {
			log.Error("edge proxy exited", "err", err)
			return err
		}
		return nil
	})

	if adminCfg := cfg.Admin; adminCfg != nil {
		deps := adminDeps(edgeSrv, opts.Version, cfg)
		adminSrv := admin.New(adminCfg, cfg.TLS, store, deps, log, opts.ConfigPath)
		g.Go(func() error {
			if err := adminSrv.Run(gctx); err != nil && gctx.Err() == nil {
				log.Error("admin server exited", "err", err)
				return err
			}
			return nil
		})
	}

	log.Info("freesbc started", "config", opts.ConfigPath)

	<-gctx.Done()
	log.Info("shutting down")
	return g.Wait()
}

// adminDeps assembles the admin API's view of the running edge plane.
func adminDeps(edgeSrv *edge.Server, version string, running *config.Config) admin.Deps {
	return admin.Deps{
		Version: version,
		// The startup snapshot: the baseline for restart-only comparison.
		Running: func() *config.Config { return running },
		Ports:   edgeSrv.PortStats,
		Calls: func() []admin.Call {
			out := []admin.Call{}
			for _, r := range edgeSrv.Calls() {
				out = append(out, admin.Call{
					ID: r.ID, CallID: r.CallID, FromPeer: r.From, ToPeer: r.To, StartUnixNano: r.StartUnixNano,
				})
			}
			return out
		},
		ActiveCalls: edgeSrv.ActiveCalls,
		Listeners:   edgeSrv.Listeners,
		Shield: func() admin.ShieldStats {
			return admin.ShieldStats{DropsByReason: edgeSrv.ShieldStats().DropsByReason}
		},
		Proxy: func() admin.ProxyStats {
			s := edgeSrv.Metrics().Snapshot()
			return admin.ProxyStats{
				ActiveRegistrations:    s.ActiveRegistrations,
				ActiveSubscriptions:    s.ActiveSubscriptions,
				ActiveDialogs:          s.ActiveDialogs,
				ActiveSessions:         s.ActiveSessions,
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
				HandlerPanics:          s.HandlerPanics,
				AdmissionDrops:         s.AdmissionDrops,
				CallsEnded:             s.CallsEnded,
				InviteRejects:          s.InviteRejects,
				ParseFailures:          s.ParseFailures,
				CarrierRequests:        s.CarrierRequests,
				CarrierRegistrations:   s.CarrierRegistrations,
			}
		},
	}
}

// testHookEdgeOptions are extra options passed to edge.New. Only tests set
// it, to override the fixed private socket (edge.WithPrivateAddr) with a
// loopback port.
var testHookEdgeOptions []edge.Option

// testHookWatchStarted, when non-nil, runs right after Run starts the
// config watcher, with the store the watcher replaces snapshots in. Only
// tests set it, to land a reload in the middle of startup.
var testHookWatchStarted func(*config.Store)

// nopWriter discards log output, for a caller that passed no logger.
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
