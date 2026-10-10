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
		deps := adminDeps(edgeSrv, opts.Version, cfg, store)
		adminSrv := admin.New(adminCfg, cfg.TLS, store, deps, log, opts.ConfigPath)
		g.Go(func() error {
			if err := adminSrv.Run(gctx); err != nil && gctx.Err() == nil {
				log.Error("admin server exited", "err", err)
				return err
			}
			return nil
		})
	}

	log.Info("freesbc started", "config", opts.ConfigPath, "version", opts.Version)

	<-gctx.Done()
	log.Info("shutting down")
	return g.Wait()
}

// adminDeps assembles the admin API's view of the running edge plane.
func adminDeps(edgeSrv *edge.Server, version string, running *config.Config, store *config.Store) admin.Deps {
	return admin.Deps{
		Version: version,
		// The startup snapshot: the baseline for restart-only comparison.
		Running: func() *config.Config { return running },
		Reload:  store.ReloadStatus,
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
		DrainState:  edgeSrv.DrainState,
		SetDraining: edgeSrv.SetDraining,
		Listeners:   edgeSrv.Listeners,
		Shield: func() admin.ShieldStats {
			return admin.ShieldStats{DropsByReason: edgeSrv.ShieldStats().DropsByReason}
		},
		Registrations: func(user string, limit, offset int) ([]admin.Registration, int) {
			page, total := edgeSrv.Registrations(user, limit, offset)
			out := make([]admin.Registration, 0, len(page))
			for _, r := range page {
				out = append(out, admin.Registration{AOR: r.AOR, User: r.User, Transport: r.Transport,
					Source: r.Source, ExpiresAt: r.ExpiresAt})
			}
			return out, total
		},
		CarrierRegistrations: func() []admin.CarrierRegistration {
			out := []admin.CarrierRegistration{}
			for _, c := range edgeSrv.CarrierRegistrations() {
				out = append(out, admin.CarrierRegistration{Carrier: c.Carrier, User: c.User,
					Token: c.Token, Node: c.Node, Expires: c.Expires})
			}
			return out
		},
		Bans: func(limit, offset int) ([]admin.Ban, int, int64) {
			page, total, rejected := edgeSrv.Bans(limit, offset)
			out := make([]admin.Ban, 0, len(page))
			for _, b := range page {
				out = append(out, admin.Ban{Source: b.Source, Kind: b.Kind, Reason: b.Reason,
					Since: b.Since, Until: b.Until})
			}
			return out, total, rejected
		},
		SwitchNodes: func() []admin.SwitchNode {
			out := []admin.SwitchNode{}
			for _, n := range edgeSrv.SwitchNodes() {
				out = append(out, admin.SwitchNode{Address: n.Address, State: n.State,
					CooldownRemaining: n.CooldownRemaining, LastFailure: n.LastFailure})
			}
			return out
		},
		Carriers: func() []admin.Carrier {
			out := []admin.Carrier{}
			for _, c := range edgeSrv.Carriers() {
				addrs := make([]admin.CarrierAddress, 0, len(c.Addresses))
				for _, a := range c.Addresses {
					addrs = append(addrs, admin.CarrierAddress{Address: a.Address, InUse: a.InUse})
				}
				out = append(out, admin.Carrier{Name: c.Name, Host: c.Host, Transport: c.Transport,
					Mode: c.Mode, Addresses: addrs, ResolvedAt: c.ResolvedAt, ExpiresAt: c.ExpiresAt,
					Failing: c.Failing, LastError: c.LastError})
			}
			return out
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
				Draining:               s.Draining,
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
				StreamConnections:      s.StreamConnections,
				StreamRefused:          s.StreamRefused,
				StreamClosed:           s.StreamClosed,
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
