package trunk

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"

	"github.com/freesbc/freesbc/internal/config"
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
	// contactExpires, when > 0, makes the 200 OK also carry a Contact
	// with an expires param of that many seconds — the RFC 3261 §10.3
	// step 7 form, where the param outranks the Expires header.
	contactExpires int
	challenge      *digest.Challenge

	mu              sync.Mutex
	authorizedCount int
	unregisterCount int
	events          []bool // one entry per authorized REGISTER, in processed order; true = un-REGISTER (Expires:0)

	// conn is the stub's own bound UDP socket (the same one REGISTER
	// traffic arrives on). Exposed so tests can send a raw packet FROM this
	// exact socket — mirroring a real carrier's OPTIONS keepalive landing on
	// the same address the SBC will later send an un-REGISTER back to (Fix
	// 1's shutdown-ordering regression test).
	conn *net.UDPConn
}

// startStubRegistrar boots the stub UAS on 127.0.0.1:port and returns once
// it is accepting packets. Follows the same bind-our-own-socket pattern as
// startStubCarrier in b2bua_test.go (avoids sipgo's known ListenAndServe
// shutdown race). Ports for this file's tests: 45320-45339.
func startStubRegistrar(t *testing.T, port int, user, pass string, grantExpires int) *stubRegistrar {
	t.Helper()
	return startStubRegistrarRealm(t, port, user, pass, grantExpires, "freesbc-test")
}

// startStubRegistrarRealm is startStubRegistrar with an explicit challenge
// realm — T-19's rogue-registrar test needs a realm the peer hasn't pinned.
// The realm is set at construction (before the handler goroutine exists),
// never mutated afterward, so -race stays clean.
func startStubRegistrarRealm(t *testing.T, port int, user, pass string, grantExpires int, realm string) *stubRegistrar {
	t.Helper()
	return startStubRegistrarFull(t, port, user, pass, grantExpires, 0, realm)
}

// startStubRegistrarFull is startStubRegistrarRealm with an extra Contact
// expires param on the 200 OK (0 = no Contact header at all, the shape
// every other test uses).
func startStubRegistrarFull(t *testing.T, port int, user, pass string, grantExpires, contactExpires int, realm string) *stubRegistrar {
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
		user:           user,
		pass:           pass,
		grantExpires:   grantExpires,
		contactExpires: contactExpires,
		challenge: &digest.Challenge{
			Realm:     realm,
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
		isUnregister := false
		if eh := req.GetHeader("Expires"); eh != nil && eh.Value() == "0" {
			r.unregisterCount++
			isUnregister = true
		}
		r.events = append(r.events, isUnregister)
		r.mu.Unlock()

		res := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil)
		exp := sip.ExpiresHeader(uint32(r.grantExpires))
		res.AppendHeader(&exp)
		if r.contactExpires > 0 {
			pr := sip.NewParams()
			pr.Add("expires", strconv.Itoa(r.contactExpires))
			res.AppendHeader(&sip.ContactHeader{
				Address: sip.Uri{User: user, Host: "127.0.0.1", Port: port},
				Params:  pr,
			})
		}
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
	r.conn = conn
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

// eventLog returns a snapshot of every authorized REGISTER the registrar has
// processed, in order, as true=un-REGISTER (Expires:0) / false=real
// register — for the Fix 2 changed-peer-restart ordering test.
func (r *stubRegistrar) eventLog() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]bool, len(r.events))
	copy(out, r.events)
	return out
}

// sendRawOptions sends a bare OPTIONS request FROM the stub's own bound
// socket (the same one all REGISTER traffic arrives on) TO targetAddr. Used
// by the Fix 1 shutdown-ordering test to mimic a real carrier's OPTIONS
// keepalive landing on the SBC's listener, attempting to seed the SBC
// transport's pooled connection for that remote address before the SBC's
// own un-REGISTER later goes out to the same address.
func (r *stubRegistrar) sendRawOptions(t *testing.T, targetAddr string) {
	t.Helper()
	dst, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}
	local := r.conn.LocalAddr().String()
	msg := strings.Join([]string{
		"OPTIONS sip:sbc@" + targetAddr + " SIP/2.0",
		"Via: SIP/2.0/UDP " + local + ";branch=z9hG4bK-optsprobe",
		"From: <sip:" + r.user + "@" + local + ">;tag=probe1",
		"To: <sip:sbc@" + targetAddr + ">",
		"Call-ID: probe-options-1",
		"CSeq: 1 OPTIONS",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
	if _, err := r.conn.WriteToUDP([]byte(msg), dst); err != nil {
		t.Fatalf("send raw options: %v", err)
	}
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

// startStubRegistrarMinExpires boots a stub UAS like startStubRegistrar, but
// enforces a registrar-side minimum lifetime: any authorized REGISTER whose
// Expires is below minExpires is rejected with 423 Interval Too Brief and a
// Min-Expires header carrying minExpires; a REGISTER meeting or exceeding it
// is granted (200, Expires: minExpires) — for Task 7's 423-retry test, which
// needs registerOnce's first attempt (below the minimum) to be rejected and
// its retry (at the minimum) to succeed.
func startStubRegistrarMinExpires(t *testing.T, port int, user, pass string, minExpires int) *stubRegistrar {
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
		grantExpires: minExpires,
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

		reqExpires := 0
		if eh := req.GetHeader("Expires"); eh != nil {
			reqExpires, _ = strconv.Atoi(eh.Value())
		}

		r.mu.Lock()
		r.authorizedCount++
		isUnregister := reqExpires == 0
		if isUnregister {
			r.unregisterCount++
		}
		r.events = append(r.events, isUnregister)
		r.mu.Unlock()

		if reqExpires < minExpires {
			res := sip.NewResponseFromRequest(req, sip.StatusIntervalToBrief, "Interval Too Brief", nil)
			me := sip.ExpiresHeader(uint32(minExpires))
			res.AppendHeader(sip.NewHeader("Min-Expires", me.Value()))
			if err := tx.Respond(res); err != nil {
				log.Error("registrar respond 423", "err", err)
			}
			return
		}

		res := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil)
		exp := sip.ExpiresHeader(uint32(minExpires))
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
	r.conn = conn
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

// TestRegisterOnceRetriesOn423 proves the Task 7 retry: the stub registrar
// rejects the first REGISTER (1800s, below its 3600s minimum) with 423 and a
// Min-Expires: 3600 header; registerOnce must read that header and retry
// once at 3600s, succeeding with a granted lifetime of 3600s.
func TestRegisterOnceRetriesOn423(t *testing.T) {
	reg := startStubRegistrarMinExpires(t, 45338, "u", "p", 3600) // 423 below 3600, then grant
	client := reg.client(t)
	p := regParams{
		Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45338,
		Transport: "udp", Username: "u", Password: "p",
		ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45995,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	granted, err := registerOnce(ctx, client, p, 1800*time.Second) // below Min-Expires 3600
	if err != nil {
		t.Fatalf("registerOnce: %v", err)
	}
	if granted != 3600*time.Second {
		t.Errorf("granted = %v, want 3600s (retried with Min-Expires)", granted)
	}
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

// TestRegisterOnceContactExpiresBeatsExpiresHeader pins RFC 3261 §10.3
// step 7: when the 200 OK carries both, the Contact's expires PARAM is
// what the registrar granted for that binding and the Expires header is
// only a default. Pre-fix the trunk plane read them the other way round
// and would have refreshed on the 3600s header while the binding expired
// after 120s.
func TestRegisterOnceContactExpiresBeatsExpiresHeader(t *testing.T) {
	// Grants Expires: 3600, but Contact: <...>;expires=120.
	reg := startStubRegistrarFull(t, 45325, "reguser", "regpass", 3600, 120, "freesbc-test")
	client := reg.client(t)
	p := regParams{
		Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45325,
		Transport: "udp", Username: "reguser", Password: "regpass",
		ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45993,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	granted, err := registerOnce(ctx, client, p, time.Hour)
	if err != nil {
		t.Fatalf("registerOnce: %v", err)
	}
	if granted != 120*time.Second {
		t.Errorf("granted = %v, want 120s (Contact expires param, not the 3600s Expires header)", granted)
	}
}

// TestRegisterRejectsUnexpectedRealm is the T-19 (F-20) red test: when the
// peer's auth pins a realm, a challenge naming any other realm must never
// be answered — no digest of our credentials leaves the SBC for it (a
// rogue or compromised registrar would harvest the response for offline
// cracking). Pre-fix, DoDigestAuth answered any challenge unconditionally.
// The matching-realm half proves the pin only blocks mismatches.
func TestRegisterRejectsUnexpectedRealm(t *testing.T) {
	// Rogue registrar: challenges with a realm the peer has NOT pinned.
	evil := startStubRegistrarRealm(t, 45321, "reguser", "regpass", 1800, "evil")
	client := evil.client(t)
	p := regParams{
		Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45321,
		Transport: "udp", Username: "reguser", Password: "regpass", Realm: "good",
		ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45997,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := registerOnce(ctx, client, p, time.Hour); err == nil {
		t.Fatal("expected error for mismatched challenge realm")
	}
	if evil.sawAuthorizedRegister() {
		t.Fatal("digest credentials must never be sent for a foreign realm")
	}

	// Matching realm: the normal digest flow resumes.
	good := startStubRegistrarRealm(t, 45323, "reguser", "regpass", 1800, "good")
	client = good.client(t)
	p.RegistrarPort = 45323
	if _, err := registerOnce(ctx, client, p, time.Hour); err != nil {
		t.Fatalf("matching realm should register: %v", err)
	}
	if !good.sawAuthorizedRegister() {
		t.Fatal("matching realm must be answered with digest")
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

// --- Task 5: Registrar manager (reconcile, IsRegistered, startup, shutdown) ---
//
// Ports for this section's tests: 45330-45349.

// registrarConfigYAML renders a config with a "carrier" peer at
// 127.0.0.1:port (credentials user/pass, register: registerCarrier) and a
// non-register "internal-pbx" peer, plus a literal public_ip and a listen.sip
// entry so sigIP/ourSigPort resolve predictably and the config validates
// (at least one listener, at least one peer). The listen.sip port here is
// never actually bound — serverForRegistrar never calls Server.Run, and
// Registrar itself never binds a socket — so it doesn't need to be distinct
// from any port a stub registrar is using.
func registrarConfigYAML(port int, user, pass string, registerCarrier bool) string {
	return fmt.Sprintf(`
listen:
  sip: [udp://127.0.0.1:45999]
  media: { port_range: 45900-45901, public_ip: 127.0.0.1 }
peers:
  carrier:
    address: 127.0.0.1:%d
    transport: udp
    auth: { username: %s, password: %s }
    register: %v
    allowed_ips: [127.0.0.1/32] # T-11: allowed_ips is required on every peer
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.10/32]
`, port, user, pass, registerCarrier)
}

// registrarTestStore builds a *config.Store with a register:true "carrier"
// peer pointing at 127.0.0.1:port (the stub registrar started by
// startStubRegistrar) plus a non-register "internal-pbx" peer, for
// Registrar.reconcile to pick up.
func registrarTestStore(t *testing.T, port int, user, pass string) *config.Store {
	t.Helper()
	cfg, err := config.Parse([]byte(registrarConfigYAML(port, user, pass, true)))
	if err != nil {
		t.Fatalf("parse registrar test config: %v", err)
	}
	return config.NewStore(cfg)
}

// withCarrierRegisterFalse returns a validated config shaped like
// registrarTestStore's, except carrier has register: false — for
// store.Replace in the hot-reload test. The registrar port/credentials here
// don't need to match the original store: a peer dropped from reconcile's
// desired set is never read for its address again — the un-REGISTER the
// test observes comes from cancelling the goroutine already running against
// the original (register:true) params.
func withCarrierRegisterFalse(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(registrarConfigYAML(45332, "u", "p", false)))
	if err != nil {
		t.Fatalf("parse withCarrierRegisterFalse config: %v", err)
	}
	return cfg
}

// serverForRegistrar builds the minimal *Server the Registrar needs: just
// enough for sigIP/ourSigPort to resolve from store's config. It never
// calls Run, so no media pool or bound socket is needed — Registrar only
// reads the Server's config-derived Contact address, it never routes or
// bridges through it (mirrors TestServerAdvertisedIPResolution.s newSrvForResolution helper in
// server_test.go, which also passes a nil pool).
func serverForRegistrar(t *testing.T, store *config.Store) *Server {
	t.Helper()
	return NewServer(store, nil, discardLogger())
}

// TestRegistrarReconcilesAndReportsRegistered proves the manager's startup
// path: reconcile (called once at the top of Run) starts a registration
// goroutine for the register:true "carrier" peer, which reports registered
// once it completes its REGISTER against the stub registrar; a non-register
// peer ("internal-pbx") reports available immediately regardless. On ctx
// cancel, Run stops the goroutine, which un-REGISTERs before Run returns.
func TestRegistrarReconcilesAndReportsRegistered(t *testing.T) {
	reg := startStubRegistrar(t, 45330, "u", "p", 120)
	// Config with one register:true peer pointing at the stub registrar.
	store := registrarTestStore(t, 45330, "u", "p") // helper builds the config
	client := reg.client(t)
	srv := serverForRegistrar(t, store) // minimal Server exposing sigIP/ourSigPort
	r := NewRegistrar(store, client, srv, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = r.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return r.IsRegistered("carrier") })
	// A non-register peer is always available.
	if !r.IsRegistered("internal-pbx") {
		t.Error("a non-register:true peer must report available")
	}
	cancel()
	waitFor(t, 3*time.Second, reg.sawUnregister)
}

// --- Changed-peer stale-write race fix: generation-guarded state writes ---

// TestSetRegisteredGenIgnoresStaleGeneration is a fully deterministic,
// non-concurrent unit test of the guard mechanism itself: setRegisteredGen
// must apply a write only when the caller's gen still matches r.epoch[name],
// and must silently drop it otherwise. This is exactly what stands between a
// superseded (changed-peer) goroutine's late setRegistered(name, false) and
// clobbering the current goroutine's live state — see the package doc on
// setRegisteredGen. No goroutines or timing are involved, so this test can
// never flake.
func TestSetRegisteredGenIgnoresStaleGeneration(t *testing.T) {
	r := NewRegistrar(nil, nil, nil, discardLogger())
	r.epoch["carrier"] = 2
	r.state["carrier"] = true

	// A stale generation (an old goroutine's leftover reference) must not
	// modify state, even though it's a live call with a valid name.
	r.setRegisteredGen("carrier", 1, false)
	if !r.state["carrier"] {
		t.Fatal("setRegisteredGen with a stale generation must not modify state")
	}

	// The current generation's write must land normally.
	r.setRegisteredGen("carrier", 2, false)
	if r.state["carrier"] {
		t.Fatal("setRegisteredGen with the current generation must update state")
	}

	// After a further bump (simulating a second reconcile), the
	// now-previous-current generation (2) becomes stale in turn, and only
	// the new current generation (3) may write.
	r.epoch["carrier"] = 3
	r.setRegisteredGen("carrier", 2, true)
	if r.state["carrier"] {
		t.Fatal("setRegisteredGen from a generation superseded again must not modify state")
	}
	r.setRegisteredGen("carrier", 3, true)
	if !r.state["carrier"] {
		t.Fatal("setRegisteredGen with the new current generation must update state")
	}
}

// registrarConfigYAMLPublicIP is registrarConfigYAML with an overridable
// public_ip, for TestRegistrarChangedPeerParamsDoNotFlapRegistered: bumping
// public_ip alone changes the resolved ContactIP (via Server.sigIP →
// Registrar.paramsFor) without touching the registrar host/port or
// credentials, so reconcile takes the changed-peer stop+start path while the
// new goroutine still registers against the very same stub registrar.
func registrarConfigYAMLPublicIP(port int, user, pass, publicIP string, registerCarrier bool) string {
	return fmt.Sprintf(`
listen:
  sip: [udp://127.0.0.1:45999]
  media: { port_range: 45900-45901, public_ip: %s }
peers:
  carrier:
    address: 127.0.0.1:%d
    transport: udp
    auth: { username: %s, password: %s }
    register: %v
    allowed_ips: [127.0.0.1/32] # T-11: allowed_ips is required on every peer
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.10/32]
`, publicIP, port, user, pass, registerCarrier)
}

// TestRegistrarChangedPeerParamsDoNotFlapRegistered drives the actual
// changed-peer reconcile path (regParams differ, not removed) end to end:
// carrier first registers normally, then a hot reload changes only
// public_ip, so reconcile cancels the old goroutine and starts a new one
// against the same stub registrar. Before the generation guard, the old
// goroutine's fast synchronous setRegistered(name, false) (from its
// cancel→unregister path) could race the new goroutine's slower
// network-bound setRegistered(name, true) with no happens-before; with the
// guard, reconcile bumps r.epoch[name] and starts the new goroutine under
// the same mu.Lock() critical section that stops the old one, so any write
// the old goroutine attempts afterward blocks on r.mu until the bump has
// already happened and is then dropped as stale — the ordering is
// structural, not timing-dependent, so asserting IsRegistered never
// observes false here is a reliable (not merely low-probability) check, on
// top of the fully deterministic unit test above.
func TestRegistrarChangedPeerParamsDoNotFlapRegistered(t *testing.T) {
	reg := startStubRegistrar(t, 45334, "u", "p", 120)
	store := registrarTestStore(t, 45334, "u", "p")
	client := reg.client(t)
	srv := serverForRegistrar(t, store)
	r := NewRegistrar(store, client, srv, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return r.IsRegistered("carrier") })

	cfg2, err := config.Parse([]byte(registrarConfigYAMLPublicIP(45334, "u", "p", "127.0.0.2", true)))
	if err != nil {
		t.Fatalf("parse changed-public-ip config: %v", err)
	}
	store.Replace(cfg2)

	// The old goroutine's un-REGISTER landing proves reconcile really took
	// the changed-peer stop+start path (not a no-op).
	waitFor(t, 3*time.Second, reg.sawUnregister)

	// The new goroutine re-registers against the same stub; wait for it,
	// then poll for a further stretch to catch any late flap to false.
	waitFor(t, 3*time.Second, func() bool { return r.IsRegistered("carrier") })
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !r.IsRegistered("carrier") {
			t.Fatal("carrier flapped to unregistered after a changed-peer (not removed) hot reload")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRegistrarHotReloadStopsRemovedPeer proves reconcile reacts to a
// Subscribe fire: flipping carrier to register:false drops it from the
// desired set, so reconcile cancels its goroutine, which un-REGISTERs
// before exiting — proving the goroutine actually stopped rather than
// being left running against a config that no longer wants it registered.
//
// This does NOT assert IsRegistered("carrier") turns false: by spec (and
// the reference implementation) a peer without register:true is always
// available, so once the peer is register:false, IsRegistered reports it
// available immediately — including in the split second right after
// store.Replace, before reconcile has even run. That's the correct
// behavior (a non-register:true peer is never gated), so the assertion
// below checks it explicitly instead of waiting on a state transition that
// IsRegistered's contract says can't happen.
func TestRegistrarHotReloadStopsRemovedPeer(t *testing.T) {
	reg := startStubRegistrar(t, 45332, "u", "p", 120)
	store := registrarTestStore(t, 45332, "u", "p")
	client := reg.client(t)
	srv := serverForRegistrar(t, store)
	r := NewRegistrar(store, client, srv, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return r.IsRegistered("carrier") })
	// Hot-reload: flip carrier to register:false → un-REGISTER + stop.
	store.Replace(withCarrierRegisterFalse(t)) // helper returns a modified config
	waitFor(t, 3*time.Second, reg.sawUnregister)
	if !r.IsRegistered("carrier") {
		t.Error("carrier is no longer register:true; IsRegistered must report it available")
	}
}

// --- Fix 2 (whole-branch review): changed-peer restart must not race the
// old goroutine's un-REGISTER against the new goroutine's REGISTER ---

// TestRegistrarChangedPeerRestartSerializesAgainstOldUnregister is Fix 2's
// regression coverage: before the fix, a changed-peer restart (regParams
// differ — e.g. a password/public_ip rotation) started the new goroutine
// immediately, without waiting for the old goroutine's Expires:0
// un-REGISTER to finish. The two REGISTERs then raced on the wire; if the
// carrier processed the old's un-REGISTER AFTER the new's real REGISTER, it
// deleted the binding the new goroutine had just (re)created — even though
// our own epoch-guarded state still said "registered" (TestSetRegisteredGen
// IgnoresStaleGeneration / TestRegistrarChangedPeerParamsDoNotFlapRegistered
// above cover that OUR bookkeeping doesn't flap; neither proves what the
// carrier actually has on file, which is what this test checks).
//
// reconcile now makes the new goroutine wait on the old goroutine's done
// channel before sending anything at all, so the old's un-REGISTER
// round-trip (its own request/response, or its bounded 2s timeout)
// structurally completes before the new REGISTER is even transmitted — this
// is an ordering guarantee, not a timing race, so asserting on it is
// reliable rather than merely low-probability (same reasoning as the
// existing changed-peer test above).
func TestRegistrarChangedPeerRestartSerializesAgainstOldUnregister(t *testing.T) {
	reg := startStubRegistrar(t, 45336, "u", "p", 120)
	store := registrarTestStore(t, 45336, "u", "p")
	client := reg.client(t)
	srv := serverForRegistrar(t, store)
	r := NewRegistrar(store, client, srv, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return r.IsRegistered("carrier") })

	// Change only public_ip: same registrar/credentials, but regParams
	// differ, so reconcile takes the changed-peer stop+start path against
	// the very same stub registrar.
	cfg2, err := config.Parse([]byte(registrarConfigYAMLPublicIP(45336, "u", "p", "127.0.0.2", true)))
	if err != nil {
		t.Fatalf("parse changed-public-ip config: %v", err)
	}
	store.Replace(cfg2)

	waitFor(t, 3*time.Second, reg.sawUnregister)
	waitFor(t, 3*time.Second, func() bool { return r.IsRegistered("carrier") })
	// Let any further refresh/backoff traffic settle before inspecting what
	// the stub actually saw, on the wire, in what order.
	time.Sleep(200 * time.Millisecond)

	events := reg.eventLog()
	if len(events) == 0 {
		t.Fatal("stub saw no authorized REGISTER at all")
	}
	if events[len(events)-1] {
		t.Fatalf("last REGISTER the stub processed was an un-REGISTER (Expires:0) — "+
			"the new registration was wiped by a raced old un-register; events=%v", events)
	}
}

// --- Fix 1 (whole-branch review): shutdown sequencing — the registrar must
// un-REGISTER before listener sockets close ---
//
// Ports for this test: 45340 (stub registrar, doubling as "the carrier"
// that probes the SBC's listener) and 45341 (the SBC's own listen.sip UDP
// port).

// TestServerShutdownDeliversUnregisterBeforeListenerCloses is Fix 1's
// regression coverage. Server.Run used to share one ctx between the
// registrar and the listener-socket watchers, so on shutdown a listener
// socket could close CONCURRENTLY with the registrar's Expires:0
// un-REGISTER. In sipgo, a UDP listener's connection is pooled per remote
// addr it has received a packet from, and an outbound request from the same
// UA/transport REUSES that pooled conn (connectionReuse default true) — so
// once a real carrier has sent inbound traffic (e.g. an OPTIONS keepalive)
// on our listener, the un-REGISTER we send back to that same carrier
// address can route onto the just-closed listener socket and fail with
// net.ErrClosed, defeating spec Decision #3 (clean shutdown un-register).
//
// This drives a real Server.Run — an actual bound UDP listener, not a mock
// — with a register:true peer pointing at a live stub registrar. Before
// triggering shutdown, the stub sends a raw OPTIONS packet to the SBC's
// listener FROM the exact socket it also receives REGISTER traffic on (the
// same shape a real carrier's keepalive takes), attempting to seed the
// SBC's transport-layer connection pool for that remote address before the
// SBC's own un-REGISTER goes out to it.
//
// sipgo's internal connection-pool selection isn't part of its public API,
// so reproducing that exact pooled-conn code path deterministically from a
// black-box test can't be fully guaranteed. What this test DOES guarantee,
// unconditionally, is the externally observable behavior Fix 1 promises:
// Server.Run's shutdown sequencing (regCancel + wait <-regDone BEFORE
// listenCancel) means the un-REGISTER attempt always completes before Run
// returns, whether or not this particular run happened to exercise the
// pooled-conn path. The sequencing itself is also verified directly by
// inspection of Run's shutdown tail (see the comment there).
func TestServerShutdownDeliversUnregisterBeforeListenerCloses(t *testing.T) {
	reg := startStubRegistrar(t, 45340, "u", "p", 120)

	cfgYAML := `
listen:
  sip: [udp://127.0.0.1:45341]
  media: { port_range: 45902-45903, public_ip: 127.0.0.1 }
peers:
  carrier:
    address: 127.0.0.1:45340
    transport: udp
    auth: { username: u, password: p }
    register: true
    allowed_ips: [127.0.0.1/32]
`
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore(cfg)
	pool := NewMediaPool(store)
	srv := NewServer(store, pool, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = srv.Run(ctx); close(runDone) }()

	// Wait until the SBC's listener answers (bind completed).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.Dial("udp", "127.0.0.1:45341")
		if derr == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Wait for the SBC to have actually registered — via the stub's own
	// (mutex-guarded) observation, not Server's internal registrar field,
	// which races with Run's own goroutine assigning it.
	waitFor(t, 3*time.Second, reg.sawAuthorizedRegister)

	// Force an inbound packet on the SBC's listener from the registrar's own
	// bound socket, attempting to seed the pooled-conn path.
	reg.sendRawOptions(t, "127.0.0.1:45341")
	time.Sleep(100 * time.Millisecond) // let the SBC's transport process it

	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Server.Run did not return after ctx cancel")
	}

	if !reg.sawUnregister() {
		t.Fatal("stub registrar never saw the Expires:0 un-REGISTER — shutdown must deliver it before Run returns")
	}
}

// TestRegistrarNATAdvertisedContact proves the REGISTER Contact advertises
// the sip.advertised_ip:sip.advertised_port pair in a bind/advertised
// topology — the Contact is the address the carrier will send inbound
// INVITEs to, so it must be the PUBLIC advertised address, never the
// private bind_ip the listener actually sits on.
func TestRegistrarNATAdvertisedContact(t *testing.T) {
	cfg, err := config.Parse([]byte(`
sip:
  bind_ip: 127.0.0.1
  bind_port: 45395
  advertised_ip: 198.51.100.7
  advertised_port: 15060
rtp:
  advertised_ip: 203.0.113.7
peers:
  carrier:
    address: 127.0.0.1:45396
    auth: { username: u, password: p }
    register: true
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: carrier
    to: [carrier]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	srv := serverForRegistrar(t, config.NewStore(cfg))
	r := NewRegistrar(config.NewStore(cfg), nil, srv, discardLogger())
	params := r.paramsFor(cfg, "carrier", cfg.Peers["carrier"])
	if params.ContactIP.String() != "198.51.100.7" {
		t.Errorf("ContactIP = %v, want sip.advertised_ip 198.51.100.7", params.ContactIP)
	}
	if params.ContactPort != 15060 {
		t.Errorf("ContactPort = %d, want sip.advertised_port 15060 (not the 45395 bind port)", params.ContactPort)
	}
}

// TestRegistrarBareHostAddressUsesTransportDefaultPort pins the registrar's
// address parsing to the same transport-aware default the outbound INVITE
// leg uses (classifyAddress + defaultPort, RFC 3263 §4.1): a peer whose
// address carries no explicit port REGISTERs on 5061 when transport is tls
// and 5060 otherwise. An explicit port always wins.
func TestRegistrarBareHostAddressUsesTransportDefaultPort(t *testing.T) {
	cfg, err := config.Parse([]byte(`
sip:
  bind_ip: 127.0.0.1
  bind_port: 45397
rtp:
  advertised_ip: 127.0.0.1
peers:
  tlsbare:
    address: tls.example.net
    transport: tls
    auth: { username: u, password: p }
    register: true
    allowed_ips: [127.0.0.1/32]
  udpbare:
    address: udp.example.net
    auth: { username: u, password: p }
    register: true
    allowed_ips: [127.0.0.1/32]
  tlsexplicit:
    address: tls.example.net:5999
    transport: tls
    auth: { username: u, password: p }
    register: true
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: tlsbare
    to: [tlsbare]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	srv := serverForRegistrar(t, config.NewStore(cfg))
	r := NewRegistrar(config.NewStore(cfg), nil, srv, discardLogger())
	for _, tc := range []struct {
		peer     string
		wantHost string
		wantPort int
	}{
		{"tlsbare", "tls.example.net", 5061},
		{"udpbare", "udp.example.net", 5060},
		{"tlsexplicit", "tls.example.net", 5999},
	} {
		params := r.paramsFor(cfg, tc.peer, cfg.Peers[tc.peer])
		if params.RegistrarHost != tc.wantHost || params.RegistrarPort != tc.wantPort {
			t.Errorf("%s: registrar = %s:%d, want %s:%d",
				tc.peer, params.RegistrarHost, params.RegistrarPort, tc.wantHost, tc.wantPort)
		}
	}
}
