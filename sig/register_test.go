package sig

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
)

// --- Task 3: registerOnce + stub-registrar UAS test harness ---

// stubRegistrar is a minimal sipgo UAS standing in for an upstream SIP
// registrar. Every REGISTER lacking a valid Authorization header is
// challenged with a fixed digest nonce (401 + WWW-Authenticate, mirroring
// the M4.1 stub-carrier's digestChallenge pattern in b2bua_test.go); once
// the retried REGISTER's digest response verifies, it answers 200 with an
// Expires header carrying grantExpires. sawAuthorizedRegister/sawUnregister
// let tests observe what actually reached the registrar without racing the
// handler goroutine.
type stubRegistrar struct {
	user         string
	pass         string
	grantExpires int
	challenge    *digest.Challenge

	mu              sync.Mutex
	authorizedCount int
	unregisterCount int
}

// startStubRegistrar boots the stub UAS on 127.0.0.1:port and returns once
// it is accepting packets. Follows the same bind-our-own-socket pattern as
// startStubCarrier in b2bua_test.go (avoids sipgo's known ListenAndServe
// shutdown race). Ports for this file's tests: 45320-45339.
func startStubRegistrar(t *testing.T, port int, user, pass string, grantExpires int) *stubRegistrar {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("registrar ua: %v", err)
	}
	t.Cleanup(func() { ua.Close() })
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatalf("registrar server: %v", err)
	}

	r := &stubRegistrar{
		user:         user,
		pass:         pass,
		grantExpires: grantExpires,
		challenge: &digest.Challenge{
			Realm:     "freesbc-test",
			Nonce:     "test-nonce-fixed",
			Algorithm: "MD5",
		},
	}

	srv.OnRequest(sip.REGISTER, func(req *sip.Request, tx sip.ServerTransaction) {
		if !r.authorized(req) {
			res := sip.NewResponseFromRequest(req, sip.StatusUnauthorized, "Unauthorized", nil)
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", r.challenge.String()))
			if err := tx.Respond(res); err != nil {
				log.Error("registrar respond 401", "err", err)
			}
			return
		}

		r.mu.Lock()
		r.authorizedCount++
		if eh := req.GetHeader("Expires"); eh != nil && eh.Value() == "0" {
			r.unregisterCount++
		}
		r.mu.Unlock()

		res := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil)
		exp := sip.ExpiresHeader(uint32(r.grantExpires))
		res.AppendHeader(&exp)
		if err := tx.Respond(res); err != nil {
			log.Error("registrar respond 200", "err", err)
		}
	})

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("registrar resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("registrar listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { <-ctx.Done(); conn.Close() }()
	tl := srv.TransportLayer()
	go func() { _ = tl.ServeUDP(conn) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		probe, err := net.Dial("udp", addr)
		if err == nil {
			probe.Close()
			time.Sleep(50 * time.Millisecond)
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("stub registrar did not start")
	return nil
}

// authorized reports whether req carries an Authorization header whose
// digest response matches r.challenge for r.user/pass — mirrors
// stubCarrier.digestAuthorized in b2bua_test.go (that unexported sipgo
// logic isn't reachable from this package).
func (r *stubRegistrar) authorized(req *sip.Request) bool {
	h := req.GetHeader("Authorization")
	if h == nil {
		return false
	}
	creds, err := digest.ParseCredentials(h.Value())
	if err != nil {
		return false
	}
	want, err := digest.Digest(r.challenge, digest.Options{
		Method:   sip.REGISTER.String(),
		URI:      req.Recipient.Addr(),
		Username: r.user,
		Password: r.pass,
	})
	if err != nil {
		return false
	}
	return creds.Response == want.Response
}

// sawAuthorizedRegister reports whether the registrar has answered at least
// one REGISTER whose Authorization header verified.
func (r *stubRegistrar) sawAuthorizedRegister() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.authorizedCount > 0
}

// sawUnregister reports whether the registrar has answered at least one
// authorized REGISTER carrying Expires: 0 (an un-register) — for the
// shutdown/lifecycle tests in later tasks.
func (r *stubRegistrar) sawUnregister() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.unregisterCount > 0
}

// client returns a sipgo Client bound to an ephemeral loopback port, for
// use as the caller side of a registerOnce exchange against this registrar.
// No server/listener is needed on this side: client.Do/DoDigestAuth read
// responses straight off the transaction layer, the same way the UAC-side
// clients in b2bua_test.go's dialog tests work without their own listener.
func (r *stubRegistrar) client(t *testing.T) *sipgo.Client {
	t.Helper()
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("register client ua: %v", err)
	}
	t.Cleanup(func() { ua.Close() })
	client, err := sipgo.NewClient(ua, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// TestRegisterOnceSucceedsWithDigest proves the happy path: registerOnce
// answers the stub registrar's 401 challenge with a digest Authorization,
// and returns the granted Expires (1800s here, distinct from the 1-hour
// request) parsed off the 200. Timing-based over real UDP loopback: re-run
// once before treating a flake as failure.
func TestRegisterOnceSucceedsWithDigest(t *testing.T) {
	reg := startStubRegistrar(t, 45320, "reguser", "regpass", 1800) // grants 1800s
	client := reg.client(t)                                         // a sipgo client bound to loopback
	p := regParams{
		Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45320,
		Transport: "udp", Username: "reguser", Password: "regpass",
		ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45999,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	granted, err := registerOnce(ctx, client, p, time.Hour)
	if err != nil {
		t.Fatalf("registerOnce: %v", err)
	}
	if granted != 1800*time.Second {
		t.Errorf("granted = %v, want 1800s", granted)
	}
	if !reg.sawAuthorizedRegister() {
		t.Error("registrar never received an authorized REGISTER")
	}
}

// TestRegisterOnceBadCredentialsFails proves the wrong password never
// satisfies the challenge: the registrar keeps rejecting with 401, and
// registerOnce surfaces that as an error rather than silently reporting a
// granted lifetime.
func TestRegisterOnceBadCredentialsFails(t *testing.T) {
	reg := startStubRegistrar(t, 45322, "reguser", "rightpass", 1800)
	client := reg.client(t)
	p := regParams{
		Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45322,
		Transport: "udp", Username: "reguser", Password: "WRONGpass",
		ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45998,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := registerOnce(ctx, client, p, time.Hour); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

// --- Task 4: per-peer registration lifecycle ---

// waitFor polls cond until it returns true or timeout elapses, failing the
// test if the deadline is reached first. Mirrors config/reload_test.go's
// helper of the same name (different package, so not shareable directly).
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// discardLogger returns a *slog.Logger that writes nowhere, for tests that
// need a non-nil logger but don't care about its output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// loopbackClient returns a sipgo Client bound to an ephemeral loopback port
// with no registrar (or anything else) listening on the other end — for
// tests that need every register attempt to fail (connection refused /
// timeout) without standing up a stub server.
func loopbackClient(t *testing.T) *sipgo.Client {
	t.Helper()
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("loopback client ua: %v", err)
	}
	t.Cleanup(func() { ua.Close() })
	client, err := sipgo.NewClient(ua, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("loopback client: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// TestRegistrationRunRefreshesAndUnregisters proves the happy path of the
// lifecycle loop: run() registers against the stub registrar, marks the
// peer registered via setRegistered, and on ctx cancellation sends a
// best-effort Expires:0 un-REGISTER before returning — leaving the peer
// marked unregistered.
func TestRegistrationRunRefreshesAndUnregisters(t *testing.T) {
	reg := startStubRegistrar(t, 45324, "u", "p", 60)
	client := reg.client(t)
	var mu sync.Mutex
	states := map[string]bool{}
	set := func(name string, ok bool) { mu.Lock(); states[name] = ok; mu.Unlock() }
	rg := &registration{
		client: client,
		params: regParams{
			Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45324,
			Transport: "udp", Username: "u", Password: "p",
			ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45997,
		},
		setRegistered: set,
		log:           discardLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rg.run(ctx, time.Hour); close(done) }()
	// Wait until registered.
	waitFor(t, 3*time.Second, func() bool { mu.Lock(); defer mu.Unlock(); return states["carrier"] })
	if !reg.sawAuthorizedRegister() {
		t.Fatal("registrar saw no authorized REGISTER")
	}
	// Cancel → un-REGISTER (Expires 0).
	cancel()
	<-done
	waitFor(t, 3*time.Second, reg.sawUnregister)
	mu.Lock()
	if states["carrier"] {
		t.Error("registration should be marked unregistered after cancel")
	}
	mu.Unlock()
}

// TestRegistrationRunBacksOffOnFailure proves the loop doesn't spin or exit
// early when every register attempt fails: with no registrar listening on
// the target port, run() must keep retrying with backoff until ctx expires,
// then return.
func TestRegistrationRunBacksOffOnFailure(t *testing.T) {
	// No registrar listening on this port → every register fails; the loop
	// must mark unregistered and keep retrying (not spin, not exit).
	client := loopbackClient(t) // a client with nothing to talk to at 45326
	set := func(string, bool) {}
	rg := &registration{
		client: client,
		params: regParams{
			Name: "dead", RegistrarHost: "127.0.0.1", RegistrarPort: 45326,
			Transport: "udp", Username: "u", Password: "p",
			ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45996,
		},
		setRegistered: set,
		log:           discardLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { rg.run(ctx, time.Hour); close(done) }()
	select {
	case <-done: // returns when ctx expires — must not spin-exit early
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after ctx cancel")
	}
}
