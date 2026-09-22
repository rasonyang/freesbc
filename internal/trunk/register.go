package trunk

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// regParams is the immutable identity of one peer's registration: what
// registrar to talk to, which credentials to present, and what Contact to
// advertise. Task 4/5's lifecycle/manager build the periodic-refresh and
// shutdown un-register logic on top of this.
type regParams struct {
	Name          string
	RegistrarHost string
	RegistrarPort int
	Transport     string
	Username      string
	Password      string
	// Realm pins the digest realm we answer challenges for (T-19/F-20);
	// empty = accept any. Part of the struct (and thus the reconcile
	// comparison) so a realm change re-registers like any other param
	// change.
	Realm       string
	ContactIP   netip.Addr
	ContactPort int
}

// registerOnce performs a REGISTER exchange for p, requesting the given
// expires (0 = un-REGISTER). It handles a 401/407 digest challenge via
// registerOnceNoRetry, and additionally applies at most one retry when the
// registrar rejects the request with 423 Interval Too Brief: it reads the
// registrar's Min-Expires and, if that minimum exceeds what was requested,
// resends once at that minimum. The retry calls registerOnceNoRetry
// directly (not registerOnce), so a registrar that keeps 423-ing above its
// own advertised Min-Expires cannot cause unbounded recursion — at most two
// REGISTER exchanges are ever sent for one registerOnce call.
func registerOnce(ctx context.Context, client *sipgo.Client, p regParams, expires time.Duration) (time.Duration, error) {
	granted, res, err := registerOnceNoRetry(ctx, client, p, expires)
	if err == nil || res == nil || res.StatusCode != sip.StatusIntervalToBrief {
		return granted, err
	}
	minExp := headerSeconds(res, "Min-Expires")
	if minExp <= expires || minExp <= 0 {
		return granted, err
	}
	granted, _, err = registerOnceNoRetry(ctx, client, p, minExp)
	return granted, err
}

// registerOnceNoRetry performs a single REGISTER exchange for p, requesting
// the given expires (0 = un-REGISTER): builds the request, sends it,
// answers a 401/407 digest challenge if offered, and parses the granted
// lifetime off a 200. It does not itself retry on 423 — that one bounded
// retry is registerOnce's job — so callers that want the 423-retry
// behavior must call registerOnce, not this directly. On a non-200 final
// response it returns the response alongside the error (registerOnce needs
// it to inspect StatusCode/Min-Expires); res may be nil if the failure was
// transport-level (no response was ever received).
func registerOnceNoRetry(ctx context.Context, client *sipgo.Client, p regParams, expires time.Duration) (time.Duration, *sip.Response, error) {
	registrar := sip.Uri{Scheme: "sip", Host: p.RegistrarHost, Port: p.RegistrarPort}
	req := sip.NewRequest(sip.REGISTER, registrar)

	// The address-of-record: no userinfo is added to the Request-URI itself
	// (ClientRequestRegisterBuild strips it per RFC 3261 §10.2 anyway), but
	// From/To carry the registering identity.
	aor := sip.Uri{Scheme: "sip", User: p.Username, Host: p.RegistrarHost}
	req.AppendHeader(&sip.FromHeader{Address: aor, Params: newTagParams()})
	req.AppendHeader(&sip.ToHeader{Address: aor, Params: sip.NewParams()})

	req.AppendHeader(buildContact(p.ContactIP, p.ContactPort, p.Transport))

	exp := sip.ExpiresHeader(uint32(expires.Seconds()))
	req.AppendHeader(&exp)

	// ClientRequestRegisterBuild fills in Via/CSeq/Call-ID/Max-Forwards (it
	// only sets a header when one isn't already present) and clears the
	// Request-URI's userinfo — must run after From/To/Contact/Expires are
	// set above, since it treats an existing CSeq as "retransmit, bump it"
	// rather than "not yet built".
	if err := sipgo.ClientRequestRegisterBuild(client, req); err != nil {
		return 0, nil, fmt.Errorf("build register: %w", err)
	}

	res, err := client.Do(ctx, req)
	if err != nil {
		return 0, nil, fmt.Errorf("register: %w", err)
	}
	if res.StatusCode == sip.StatusUnauthorized || res.StatusCode == sip.StatusProxyAuthRequired {
		// T-19 (F-20): when this peer pins a realm, a challenge naming any
		// other realm is never answered — computing a digest of our
		// credentials for it would let a rogue registrar harvest the
		// response for offline cracking. Fail the registration as-is.
		if p.Realm != "" && challengeRealm(res) != p.Realm {
			return 0, res, fmt.Errorf("register challenge realm %q does not match pinned realm %q", challengeRealm(res), p.Realm)
		}
		res, err = client.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: p.Username, Password: p.Password})
		if err != nil {
			return 0, nil, fmt.Errorf("register digest: %w", err)
		}
	}
	if res.StatusCode != sip.StatusOK {
		return 0, res, fmt.Errorf("register rejected: %d %s", res.StatusCode, res.Reason)
	}
	return fsip.GrantedExpires(res, expires), res, nil
}

// newTagParams returns header params carrying a fresh From tag (reuses
// freshTag, the M4.1 helper in b2bua.go).
func newTagParams() sip.HeaderParams {
	pr := sip.NewParams()
	pr.Add("tag", freshTag())
	return pr
}

const (
	// regBackoffMin is the initial retry delay after a failed register.
	regBackoffMin = 5 * time.Second
	// regBackoffMax is the ceiling the exponential backoff saturates at.
	regBackoffMax = 60 * time.Second
	// regRefreshFloor is the minimum delay before a refresh REGISTER, even
	// if 0.9x the granted lifetime would be shorter (guards against a
	// registrar granting a very short lifetime causing a refresh storm).
	regRefreshFloor = 10 * time.Second
)

// registration runs one peer's register→refresh→backoff loop. It is built
// by the manager (Task 5), one per configured outbound-register peer.
type registration struct {
	client        *sipgo.Client
	params        regParams
	setRegistered func(name string, ok bool)
	log           *slog.Logger
}

// run blocks until ctx is cancelled, keeping the peer registered: it
// registers, marks the peer registered, refreshes at ~0.9×granted (floor
// regRefreshFloor), and on any failure marks it unregistered and retries
// with exponential backoff (regBackoffMin doubling to regBackoffMax, reset
// to regBackoffMin on the next success). On ctx cancellation it best-effort
// un-REGISTERs before returning.
func (rg *registration) run(ctx context.Context, requested time.Duration) {
	backoff := regBackoffMin
	for {
		granted, err := registerOnce(ctx, rg.client, rg.params, requested)
		if ctx.Err() != nil {
			break
		}
		var wait time.Duration
		if err != nil {
			rg.setRegistered(rg.params.Name, false)
			rg.log.Warn("register failed", "peer", rg.params.Name, "err", err, "retry_in", backoff)
			wait = backoff
			if backoff *= 2; backoff > regBackoffMax {
				backoff = regBackoffMax
			}
		} else {
			rg.setRegistered(rg.params.Name, true)
			backoff = regBackoffMin
			wait = time.Duration(float64(granted) * 0.9)
			if wait < regRefreshFloor {
				wait = regRefreshFloor
			}
			rg.log.Info("registered", "peer", rg.params.Name, "granted", granted, "refresh_in", wait)
		}
		select {
		case <-ctx.Done():
			rg.unregister()
			return
		case <-time.After(wait):
		}
	}
	rg.unregister()
}

// unregister sends a best-effort Expires:0 REGISTER, bounded to a fixed
// timeout independent of the (already-cancelled) run loop's ctx, and marks
// the peer unregistered regardless of whether the registrar could be
// reached — the peer should not be treated as registered once we've
// stopped refreshing it.
func (rg *registration) unregister() {
	rg.setRegistered(rg.params.Name, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := registerOnce(ctx, rg.client, rg.params, 0); err != nil {
		rg.log.Debug("un-register failed", "peer", rg.params.Name, "err", err)
	}
}

// Registrar manages outbound REGISTER for all register:true peers: one
// registration goroutine per peer, reconciled against config on hot reload.
type Registrar struct {
	store  *config.Store
	client *sipgo.Client
	srv    *Server
	log    *slog.Logger

	mu      sync.RWMutex
	state   map[string]bool        // peer name → registered
	running map[string]*runningReg // peer name → active goroutine handle
	epoch   map[string]int         // peer name → current generation counter
}

// runningReg is the manager's handle on one peer's live registration
// goroutine: the params it was started with (for change-detection in
// reconcile), the cancel that tells registration.run to un-REGISTER and
// return, and a channel closed once it has.
type runningReg struct {
	params regParams
	cancel context.CancelFunc
	done   chan struct{}
}

// NewRegistrar builds a Registrar over store's config, using client to send
// REGISTERs and srv to resolve our own Contact address (sigIP/ourSigPort).
// Callers must call Run to start reconciling.
func NewRegistrar(store *config.Store, client *sipgo.Client, srv *Server, log *slog.Logger) *Registrar {
	return &Registrar{
		store: store, client: client, srv: srv, log: log,
		state: map[string]bool{}, running: map[string]*runningReg{},
		epoch: map[string]int{},
	}
}

// IsRegistered reports whether the bridge may route to this peer now. A peer
// without register:true is always available; a register:true peer is
// available only while its registration is live. An unknown peer name (not
// in the current config) also reports available — routing itself is
// responsible for rejecting calls to unknown peers; IsRegistered only gates
// on registration state.
func (r *Registrar) IsRegistered(name string) bool {
	cfg := r.store.Current()
	p := cfg.Peers[name]
	if p == nil || !p.Register {
		return true
	}
	r.mu.RLock()
	ok := r.state[name]
	r.mu.RUnlock()
	return ok
}

// setRegisteredGen records a peer's registration state only if the calling
// goroutine is still the current generation for that peer. A goroutine
// superseded by a reconcile (peer params changed) has an older gen, so its
// late writes are ignored — preventing a stale un-register from clobbering
// the new goroutine's live state.
func (r *Registrar) setRegisteredGen(name string, gen int, ok bool) {
	r.mu.Lock()
	if r.epoch[name] == gen {
		r.state[name] = ok
	}
	r.mu.Unlock()
}

// Run reconciles registrations against config until ctx is cancelled, then
// stops every peer goroutine (each un-REGISTERs) and returns once they exit.
// It always returns nil: there is no fatal-error case here, only ctx
// cancellation (individual peer register failures are handled inside
// registration.run's own retry/backoff loop and never propagate here).
func (r *Registrar) Run(ctx context.Context) error {
	sub := r.store.Subscribe()
	r.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			r.stopAll()
			return nil
		case <-sub:
			r.reconcile(ctx)
		}
	}
}

// reconcile diffs the desired register:true (with auth) peer set against the
// running set: peers removed from config, or whose regParams changed, are
// stopped (their goroutine un-REGISTERs on cancel); peers newly added, or
// re-added after a change-triggered stop, are started.
func (r *Registrar) reconcile(ctx context.Context) {
	cfg := r.store.Current()
	desired := map[string]regParams{}
	for name, p := range cfg.Peers {
		if p.Register && p.Auth != nil {
			desired[name] = r.paramsFor(cfg, name, p)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Stop removed or changed. For a changed (not removed) peer, record the
	// stopped handle's done channel by name: the start loop below uses it so
	// the replacement goroutine can wait for the old one's un-REGISTER to
	// actually land before it sends anything of its own (see the start loop
	// for why that ordering matters).
	stoppedDone := map[string]chan struct{}{}
	for name, rr := range r.running {
		if d, ok := desired[name]; !ok || d != rr.params {
			rr.cancel()
			stoppedDone[name] = rr.done
			delete(r.running, name)
		}
	}
	// Start added or changed (re-added after the stop above).
	for name, d := range desired {
		if _, ok := r.running[name]; ok {
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		r.epoch[name]++
		gen := r.epoch[name]
		setRegistered := func(name string, ok bool) { r.setRegisteredGen(name, gen, ok) }
		rg := &registration{client: r.client, params: d, setRegistered: setRegistered, log: r.log}
		requested := r.requestedExpires(cfg, name)
		// oldDone is nil for a fresh add; for a restart (changed peer) it is
		// the just-stopped goroutine's done channel. Without waiting on it,
		// the old goroutine's Expires:0 un-REGISTER and this new goroutine's
		// real REGISTER race on the wire — if the carrier applies the
		// un-REGISTER second, it deletes the binding the new goroutine just
		// created, while our own epoch-guarded state still says
		// "registered" (that guard only protects our bookkeeping, not what
		// the carrier actually has on file). Waiting serializes the two: the
		// old REGISTER exchange (send + receive, or its own bounded 2s
		// timeout) fully completes before the new one is even sent.
		oldDone := stoppedDone[name]
		go func() {
			// This wait MUST happen here, inside the goroutine — never
			// synchronously in reconcile while r.mu is held. The old
			// goroutine's unregister() path ends by calling
			// setRegisteredGen, which itself takes r.mu; blocking on oldDone
			// under r.mu would deadlock reconcile against the very
			// goroutine it just cancelled.
			if oldDone != nil {
				<-oldDone
			}
			rg.run(cctx, requested)
			close(done)
		}()
		r.running[name] = &runningReg{params: d, cancel: cancel, done: done}
	}
}

// stopAll cancels every running peer goroutine and waits for each to finish
// un-REGISTERing (bounded by registration.unregister's own 2s timeout), so
// Run does not return until every outstanding REGISTER has been retracted.
func (r *Registrar) stopAll() {
	r.mu.Lock()
	handles := make([]*runningReg, 0, len(r.running))
	for name, rr := range r.running {
		rr.cancel()
		handles = append(handles, rr)
		delete(r.running, name)
	}
	r.mu.Unlock()
	for _, rr := range handles {
		<-rr.done
	}
}

// paramsFor builds the immutable regParams for a register:true peer: the
// registrar host/port parsed from its configured address, and our own
// Contact IP/port resolved fresh from cfg (so a hot-reloaded advertised
// address or listener takes effect on the next reconcile without a
// restart). The Contact advertises our SIGNALING identity (sigIP/
// ourSigPort — sip.advertised_ip:advertised_port in a NAT/VPN topology):
// it is the address the carrier will send inbound INVITEs to, so it must
// be the advertised one, never the private bind address.
func (r *Registrar) paramsFor(cfg *config.Config, name string, p *config.Peer) regParams {
	// classifyAddress + defaultPort is the same address parsing the B2BUA's
	// outbound leg does (see Resolver.Resolve): a bare host defaults to the
	// transport's own SIP port, so a transport: tls peer REGISTERs on 5061
	// exactly as its INVITEs go out on 5061.
	host, port, explicitPort, _ := classifyAddress(p.Address)
	if !explicitPort {
		port = fsip.DefaultPort(p.Transport)
	}
	sigIP := r.srv.sigIP(cfg)
	return regParams{
		Name: name, RegistrarHost: host, RegistrarPort: port,
		Transport: p.Transport, Username: p.Auth.Username, Password: p.Auth.Password, Realm: p.Auth.Realm,
		ContactIP: sigIP, ContactPort: r.srv.ourSigPort(cfg, p.Transport),
	}
}

// requestedExpires returns the peer's register_expires override, or the
// config-global default when the peer doesn't set one.
func (r *Registrar) requestedExpires(cfg *config.Config, name string) time.Duration {
	if p := cfg.Peers[name]; p != nil && p.RegisterExpires != 0 {
		return p.RegisterExpires.Std()
	}
	return cfg.RegisterExpires.Std()
}
