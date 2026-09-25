// Package app owns construction and lifecycle: it turns a config file path
// into a running set of components (config watcher, trunk B2BUA plane, edge
// proxy plane, admin HTTP surface) and runs them until the context is
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
	"github.com/freesbc/freesbc/internal/media"
	"github.com/freesbc/freesbc/internal/trunk"
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

	pool := trunk.NewMediaPool(store)

	// The trunk B2BUA plane runs only when there are trunks to serve. A
	// proxy-only deployment configures no peers and no listen.sip, and
	// starting the trunk listeners there would bind ports nothing uses.
	// Validation guarantees the two go together: a trunk listener with no
	// peers is rejected at load time, so "no peers" really does mean "no
	// trunk plane" rather than a silently dead listener.
	var sipServer *trunk.Server
	if len(cfg.Peers) > 0 {
		sipServer = trunk.NewServer(store, pool, log)
	}

	// The edge proxy plane: public SIP/UDP + WS/WSS toward phones and
	// browsers, one upstream FreeSWITCH, media anchored through the SBC.
	// Entirely independent of the trunk plane above — its own user agent,
	// listeners and media pools — so either may run alone or both together.
	var edgeSrv *edge.Server
	if cfg.ProxyEnabled() {
		edgeSrv, err = edge.New(store, log)
		if err != nil {
			return fmt.Errorf("edge proxy: %w", err)
		}
	}
	if sipServer == nil && edgeSrv == nil {
		return fmt.Errorf("nothing to run: configure trunk peers, sip.upstream.address (or sip.upstreams.nodes), or both")
	}
	logMediaPlanes(log, cfg, sipServer != nil, edgeSrv != nil)

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

	if sipServer != nil {
		g.Go(func() error {
			if err := sipServer.Run(gctx); err != nil && gctx.Err() == nil {
				log.Error("sip server exited", "err", err)
				return err
			}
			return nil
		})
	}
	if edgeSrv != nil {
		g.Go(func() error {
			if err := edgeSrv.Run(gctx); err != nil && gctx.Err() == nil {
				log.Error("edge proxy exited", "err", err)
				return err
			}
			return nil
		})
	}

	if adminCfg := cfg.Admin; adminCfg != nil {
		deps := adminDeps(store, pool, sipServer, edgeSrv, opts.Version)
		adminSrv := admin.New(adminCfg, store, deps, log, opts.ConfigPath)
		g.Go(func() error {
			if err := adminSrv.Run(gctx); err != nil && gctx.Err() == nil {
				log.Error("admin server exited", "err", err)
				return err
			}
			return nil
		})
	}

	log.Info("freesbc started",
		"config", opts.ConfigPath,
		"peers", len(cfg.Peers),
		"routes", len(cfg.Routes))

	<-gctx.Done()
	log.Info("shutting down")
	return g.Wait()
}

// adminDeps assembles the admin API's view of whichever planes are
// running. Either plane may be absent (a proxy-only or trunk-only
// deployment), so every accessor covers exactly the planes that run: the
// call count and the call list agree, the port usage is that of the
// running planes' pools, and the listeners are the ones they bound.
//
// Known gap: kill-call and the shield counters are trunk-only. A
// proxy-only deployment therefore has a no-op DELETE /api/calls/{id} (404
// for an edge call) and zeroed shield drop counters even though the edge
// plane has a shield of its own.
func adminDeps(store *config.Store, pool *media.PlanePool, sipServer *trunk.Server, edgeSrv *edge.Server, version string) admin.Deps {
	deps := admin.Deps{
		Version: version,
		Ports: func() (inUse, total int) {
			if sipServer != nil {
				inUse, total = pool.Stats()
			}
			if edgeSrv != nil {
				u, t := edgeSrv.PortStats()
				inUse, total = inUse+u, total+t
			}
			return inUse, total
		},
		Calls: func() []admin.Call {
			out := []admin.Call{}
			if sipServer != nil {
				for _, r := range sipServer.Calls() {
					out = append(out, admin.Call{
						ID: r.ID, CallID: r.CallID, FromPeer: r.FromPeer, ToPeer: r.ToPeer, StartUnixNano: r.StartUnixNano,
					})
				}
			}
			if edgeSrv != nil {
				for _, r := range edgeSrv.Calls() {
					out = append(out, admin.Call{
						ID: r.ID, CallID: r.CallID, FromPeer: r.From, ToPeer: r.To, StartUnixNano: r.StartUnixNano,
					})
				}
			}
			return out
		},
		ActiveCalls: func() int {
			n := 0
			if sipServer != nil {
				n += sipServer.ActiveCalls()
			}
			if edgeSrv != nil {
				n += edgeSrv.ActiveCalls()
			}
			return n
		},
		Listeners: func() []string {
			var out []string
			if sipServer != nil {
				out = append(out, sipServer.Listeners()...)
			}
			if edgeSrv != nil {
				out = append(out, edgeSrv.Listeners()...)
			}
			return out
		},
		KillCall: func(string) bool { return false },
		Shield:   func() admin.ShieldStats { return admin.ShieldStats{DropsByReason: map[string]int64{}} },
		Peers:    func() []admin.PeerStatus { return nil },
	}
	if sipServer != nil {
		deps.KillCall = sipServer.KillCall
		deps.Shield = func() admin.ShieldStats {
			st := sipServer.ShieldStats()
			return admin.ShieldStats{DropsByReason: st.DropsByReason}
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
	if edgeSrv != nil {
		deps.Proxy = func() admin.ProxyStats {
			s := edgeSrv.Metrics().Snapshot()
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
				HandlerPanics:          s.HandlerPanics,
			}
		}
	}
	return deps
}

// logMediaPlanes logs the RTP range of each running plane: the trunk's
// effective range (rtp.port_min/max or listen.media.port_range) and the
// edge's public and private pools.
func logMediaPlanes(log *slog.Logger, cfg *config.Config, trunkOn, edgeOn bool) {
	rng := func(lo, hi int) string { return fmt.Sprintf("%d-%d", lo, hi) }
	if trunkOn {
		r := cfg.RTPPortRange()
		log.Info("media plane ready", "plane", "trunk", "port_range", rng(int(r.Min), int(r.Max)),
			"rtp_timeout", cfg.Listen.Media.RTPTimeout.Std())
	}
	if edgeOn {
		log.Info("media plane ready", "plane", "edge",
			"public_port_range", rng(cfg.RTP.Public.PortMin, cfg.RTP.Public.PortMax),
			"private_port_range", rng(cfg.RTP.Private.PortMin, cfg.RTP.Private.PortMax),
			"rtp_timeout", cfg.Listen.Media.RTPTimeout.Std())
	}
}

// testHookWatchStarted, when non-nil, runs right after Run starts the
// config watcher, with the store the watcher replaces snapshots in. Only
// tests set it, to land a reload in the middle of startup.
var testHookWatchStarted func(*config.Store)

// nopWriter discards log output, for a caller that passed no logger.
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
