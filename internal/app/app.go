// Package app owns construction and lifecycle: it turns a config file path
// into a running set of components (config watcher, edge,
// admin HTTP surface) and runs them until the context is
// cancelled or one of them fails. cmd/freesbc does argv parsing and exit
// codes; everything else lives here.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/freesbc/freesbc/internal/admin"
	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/edge"
	"github.com/freesbc/freesbc/internal/hep"
)

// Options are Run's inputs. Log and Version are optional; ConfigPath is not.
type Options struct {
	ConfigPath string
	Log        *slog.Logger
	Version    string
}

// Check validates a config file without starting anything. note is extra
// text for the caller to print after the success message: the 1:1 NAT
// port-forward checklist, empty otherwise.
func Check(path string) (note string, err error) {
	cfg, err := config.Load(path)
	if err != nil {
		return "", err
	}
	return cfg.NATChecklist(), nil
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

	if cfg.NATMode() {
		// Whether the router forwards these ports cannot be probed from
		// here; a missing one shows up as calls that die at 32 s (ACK missed).
		fw := cfg.NATForwards()
		ports := make([]string, len(fw))
		for i, f := range fw {
			ports[i] = f.String()
		}
		log.Warn("NAT: the router must forward these ports to public.bind, same numbers unless shown external->internal (edge.advertise; never the rtp range); in-dialog requests (2xx ACK, BYE) use Contact/Record-Route, not Via",
			"advertised", cfg.Public.IP, "forward_to", cfg.Public.Bind, "ports", ports)
	}

	// The edge: public SIP/UDP + WS/WSS toward phones, browsers and
	// carriers, the switch behind it, media anchored through the SBC.
	edgeOpts := append([]edge.Option(nil), testHookEdgeOptions...)
	var hepSender *hep.Sender
	if cfg.HEP != nil {
		hepSender, err = newHEPSender(cfg.HEP, log)
		if err != nil {
			return fmt.Errorf("hep: %w", err)
		}
		// Closed after every component has stopped (g.Wait below runs
		// before this), so the queue is flushed after the last message.
		defer closeHEPSender(hepSender, log)
		edgeOpts = append(edgeOpts, edge.WithHEP(hepSender))
		log.Info("HEP mirror enabled", "address", cfg.HEP.Address, "transport", cfg.HEP.Transport,
			"capture_id", cfg.HEP.CaptureID, "redact_auth", cfg.HEPRedact())
	}
	edgeSrv, err := edge.New(store, log, edgeOpts...)
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
		if hepSender != nil {
			deps.HEP = hepStats(hepSender)
		}
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

// newHEPSender builds the HEP sender from the hep section. It dials nothing:
// the sender connects on its first packet, so a collector that is down at
// startup is not fatal.
func newHEPSender(h *config.HEPConfig, log *slog.Logger) (*hep.Sender, error) {
	opts := hep.Options{
		Network:   h.Transport,
		Addr:      h.Address,
		CaptureID: h.CaptureID,
		NodeName:  h.NodeName,
		Logger:    log.With("component", "hep"),
	}
	if h.Transport == config.HEPTLS {
		var err error
		if opts.TLS, err = hepTLSConfig(h); err != nil {
			return nil, err
		}
	}
	return hep.New(opts)
}

// hepTLSConfig is the client TLS config toward a tls collector, the one
// `run` and `check --deploy` both build.
func hepTLSConfig(h *config.HEPConfig) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(h.Address)
	if err != nil {
		return nil, err
	}
	var ca, cert, key string
	if h.TLS != nil {
		ca, cert, key = h.TLS.CA, h.TLS.Cert, h.TLS.Key
	}
	return hep.TLSConfig(ca, cert, key, host)
}

// closeHEPSender flushes the queue, bounded, at shutdown.
func closeHEPSender(s *hep.Sender, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		log.Warn("HEP sender closed with packets unsent", "err", err)
	}
}

// hepStats adapts the sender's counters for /metrics.
func hepStats(s *hep.Sender) func() *admin.HEPStats {
	return func() *admin.HEPStats {
		st := s.Stats()
		return &admin.HEPStats{Sent: st.Sent, Dropped: st.Dropped, WriteErrors: st.WriteErrors, EncodeErrors: st.EncodeErrors}
	}
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
		ListenerInfos: func() []admin.Listener {
			out := []admin.Listener{}
			for _, l := range edgeSrv.ListenerInfos() {
				out = append(out, admin.Listener{Transport: l.Transport, Bind: l.Bind, Advertised: l.Advertised, Private: l.Private})
			}
			return out
		},
		TLSCert: edgeSrv.TLSCert,
		Health:  newHealthSource(edgeSrv, running, store.ReloadStatus).conditions,
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
		Offenders: func(limit int) ([]admin.Offender, int) {
			top, total := edgeSrv.Offenders(limit)
			out := make([]admin.Offender, 0, len(top))
			for _, o := range top {
				out = append(out, admin.Offender{Source: o.Source, Reason: o.Reason,
					Strikes: o.Strikes, Since: o.Since, Until: o.Until})
			}
			return out, total
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
				RegisterAuthFailures:   s.RegisterAuthFailures,
				RegisterUnanswered:     s.RegisterUnanswered,
				RegisterBreakerRejects: s.RegisterBreakerRejects,
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
				AckMissed:              s.AckMissed,
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
