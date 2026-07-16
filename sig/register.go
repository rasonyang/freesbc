package sig

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/config"
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
	ContactIP     netip.Addr
	ContactPort   int
}

// registerOnce performs a single REGISTER exchange for p, requesting the
// given expires (0 = un-REGISTER). It handles a 401/407 digest challenge
// and returns the lifetime the registrar granted, or an error.
func registerOnce(ctx context.Context, client *sipgo.Client, p regParams, expires time.Duration) (time.Duration, error) {
	registrar := sip.Uri{Scheme: "sip", Host: p.RegistrarHost, Port: p.RegistrarPort}
	req := sip.NewRequest(sip.REGISTER, registrar)

	// The address-of-record: no userinfo is added to the Request-URI itself
	// (ClientRequestRegisterBuild strips it per RFC 3261 §10.2 anyway), but
	// From/To carry the registering identity.
	aor := sip.Uri{Scheme: "sip", User: p.Username, Host: p.RegistrarHost}
	req.AppendHeader(&sip.FromHeader{Address: aor, Params: newTagParams()})
	req.AppendHeader(&sip.ToHeader{Address: aor, Params: sip.NewParams()})

	contact := sip.Uri{Scheme: "sip", Host: p.ContactIP.String(), Port: p.ContactPort}
	if p.Transport != "" && p.Transport != "udp" {
		params := sip.NewParams()
		params.Add("transport", p.Transport)
		contact.UriParams = params
	}
	req.AppendHeader(&sip.ContactHeader{Address: contact})

	exp := sip.ExpiresHeader(uint32(expires.Seconds()))
	req.AppendHeader(&exp)

	// ClientRequestRegisterBuild fills in Via/CSeq/Call-ID/Max-Forwards (it
	// only sets a header when one isn't already present) and clears the
	// Request-URI's userinfo — must run after From/To/Contact/Expires are
	// set above, since it treats an existing CSeq as "retransmit, bump it"
	// rather than "not yet built".
	if err := sipgo.ClientRequestRegisterBuild(client, req); err != nil {
		return 0, fmt.Errorf("build register: %w", err)
	}

	res, err := client.Do(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("register: %w", err)
	}
	if res.StatusCode == sip.StatusUnauthorized || res.StatusCode == sip.StatusProxyAuthRequired {
		res, err = client.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: p.Username, Password: p.Password})
		if err != nil {
			return 0, fmt.Errorf("register digest: %w", err)
		}
	}
	if res.StatusCode != sip.StatusOK {
		return 0, fmt.Errorf("register rejected: %d %s", res.StatusCode, res.Reason)
	}
	return grantedExpires(res, expires), nil
}

// grantedExpires reads the lifetime the registrar granted: the Expires
// header if present, else the Contact's expires param, else whatever was
// requested (a registrar that omits both but still answers 200 is assumed
// to have granted what was asked).
func grantedExpires(res *sip.Response, requested time.Duration) time.Duration {
	if h := res.GetHeader("Expires"); h != nil {
		if n, err := strconv.Atoi(h.Value()); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	if c := res.Contact(); c != nil {
		if v, ok := c.Params.Get("expires"); ok {
			if n, err := strconv.Atoi(v); err == nil {
				return time.Duration(n) * time.Second
			}
		}
	}
	return requested
}

// newTagParams returns header params carrying a fresh From tag (reuses
// freshTag, the M4.1 helper in sig/b2bua.go).
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
// REGISTERs and srv to resolve our own Contact address (ourIP/ourSigPort).
// Callers must call Run to start reconciling.
func NewRegistrar(store *config.Store, client *sipgo.Client, srv *Server, log *slog.Logger) *Registrar {
	return &Registrar{
		store: store, client: client, srv: srv, log: log,
		state: map[string]bool{}, running: map[string]*runningReg{},
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

// setRegistered records name's current registration state, for
// registration.run to report through and IsRegistered to read.
func (r *Registrar) setRegistered(name string, ok bool) {
	r.mu.Lock()
	r.state[name] = ok
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

	// Stop removed or changed.
	for name, rr := range r.running {
		if d, ok := desired[name]; !ok || d != rr.params {
			rr.cancel()
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
		rg := &registration{client: r.client, params: d, setRegistered: r.setRegistered, log: r.log}
		requested := r.requestedExpires(cfg, name)
		go func() { rg.run(cctx, requested); close(done) }()
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
// Contact IP/port resolved fresh from cfg (so a hot-reloaded public_ip or
// listener takes effect on the next reconcile without a restart).
func (r *Registrar) paramsFor(cfg *config.Config, name string, p *config.Peer) regParams {
	host, port := splitHostPortDefault(p.Address, 5060)
	ourIP := r.srv.ourIP(cfg)
	return regParams{
		Name: name, RegistrarHost: host, RegistrarPort: port,
		Transport: p.Transport, Username: p.Auth.Username, Password: p.Auth.Password,
		ContactIP: ourIP, ContactPort: r.srv.ourSigPort(cfg, p.Transport),
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

// splitHostPortDefault parses "host:port" into its parts, defaulting the
// port to defPort when addr carries none (net.SplitHostPort errors on a
// bare host). Mirrors peerURI's inline address parsing in b2bua.go — kept
// separate since peerURI returns a sip.Uri (with transport params for the
// B2BUA's outbound leg) rather than the (host, port) pair reconcile needs to
// build a regParams.
func splitHostPortDefault(addr string, defPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, defPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, defPort
	}
	return host, port
}
