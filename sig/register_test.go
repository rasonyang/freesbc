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
