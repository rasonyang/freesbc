package trunk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// startServer boots a trunk.Server on the given UDP port with the given
// config YAML and returns once it is accepting packets. The server stops
// when the test ends. The returned *Server lets tests reach into
// package-private state (registry, pool) for assertions.
func startServer(t *testing.T, port int, cfgYAML string) *Server {
	t.Helper()
	return startServerConfigured(t, port, cfgYAML, nil)
}

// startServerConfigured is startServer with a hook to mutate the *Server
// before Run starts — e.g. to install a resolver lookupSRV stub. The hook
// runs before the Run goroutine is spawned, so its writes happen-before any
// call-handling goroutine reads them (no data race under -race).
func startServerConfigured(t *testing.T, port int, cfgYAML string, configure func(*Server)) *Server {
	t.Helper()
	return startServerAt(t, port, "127.0.0.1", cfgYAML, configure)
}

// startServerAt is startServerConfigured with an explicit listener host,
// kept in the signature for tests whose config binds a non-127.0.0.1
// loopback address (e.g. server_preparse_test.go's 127.0.0.2) — it now only
// labels failures, since readiness is proved by the server, not by a probe
// against that host.
//
// Readiness MUST be a real bind check, never a UDP "probe dial":
// net.Dial("udp", addr) only sets a route on a connectionless socket and
// succeeds even when nothing is bound, so a listener that failed to bind
// (e.g. 127.0.0.2 on a host where that loopback alias doesn't exist) used to
// look "ready". Every test that asserts "no response means the packet was
// dropped" then passed vacuously against a server that never listened. So:
// wait for srv.onListening — fired once per listener socket after its bind
// succeeds — and race it against Run's error, which is captured on a channel
// and reported from THIS goroutine (t.Fatalf is illegal from the Run
// goroutine). A bind failure now fails the test immediately, with the error.
func startServerAt(t *testing.T, port int, probeHost string, cfgYAML string, configure func(*Server)) *Server {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore(cfg)
	pool := NewMediaPool(store)
	srv := NewServer(store, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	listeners := cfg.Listeners()
	bound := make(chan config.SIPListen, len(listeners)+1)
	// Set before configure so a caller hook could still override it, and
	// before the Run goroutine spawns so the write happens-before the read.
	srv.onListening = func(l config.SIPListen) { bound <- l }
	if configure != nil {
		configure(srv)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()
	exited := false
	t.Cleanup(func() {
		cancel()
		if exited {
			return // already drained (and reported) below
		}
		select {
		case err := <-runErr:
			// Cancellation is the normal teardown path; anything else is a
			// real failure worth surfacing.
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("sip server Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("sip server did not shut down within 10s")
		}
	})
	target := net.JoinHostPort(probeHost, fmt.Sprintf("%d", port))
	deadline := time.After(5 * time.Second)
	for n := 0; n < len(listeners); n++ {
		select {
		case <-bound:
		case err := <-runErr:
			exited = true
			t.Fatalf("sip server (%s) exited before all %d listener(s) bound (%d up): %v",
				target, len(listeners), n, err)
		case <-deadline:
			t.Fatalf("sip server (%s) bound only %d of %d listener(s) within 5s",
				target, n, len(listeners))
		}
	}
	// The sockets are bound; give the transport read loops a moment to
	// start before the caller sends traffic.
	time.Sleep(100 * time.Millisecond)
	return srv
}

// sipRequest builds a minimal valid SIP request whose Via advertises
// localAddr so the response returns to our socket.
func sipRequest(method, targetPort string, localAddr *net.UDPAddr, callID string) string {
	return strings.Join([]string{
		fmt.Sprintf("%s sip:sbc@127.0.0.1:%s SIP/2.0", method, targetPort),
		fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-%s", localAddr.String(), callID),
		"From: <sip:tester@127.0.0.1>;tag=t1",
		"To: <sip:sbc@127.0.0.1>",
		"Call-ID: " + callID,
		fmt.Sprintf("CSeq: 1 %s", method),
		"Contact: <sip:tester@" + localAddr.String() + ">",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
}

// roundTrip sends one request and collects response datagrams until it
// sees wantSubstr or the timeout elapses. Returns all received text.
func roundTrip(t *testing.T, targetPort int, method, callID string, timeout time.Duration, wantSubstr string) string {
	t.Helper()
	return roundTripWithHeaders(t, targetPort, method, callID, timeout, wantSubstr)
}

// roundTripWithHeaders is roundTrip plus the ability to inject extra raw
// header lines (e.g. "Require: 100rel", "Session-Expires: 30") into the
// request built by sipRequest, for tests that need to exercise header-driven
// gating without hand-rolling the whole request. roundTrip is a thin
// zero-extra-headers wrapper around this.
func roundTripWithHeaders(t *testing.T, targetPort int, method, callID string, timeout time.Duration, wantSubstr string, extraHeaders ...string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort}
	req := sipRequest(method, fmt.Sprintf("%d", targetPort), local, callID)
	if len(extraHeaders) > 0 {
		// sipRequest terminates with "\r\n\r\n" (blank line ends the
		// header block, no body). Splice the extra header lines in just
		// before that blank line so they land in the header section.
		const terminator = "\r\n\r\n"
		if !strings.HasSuffix(req, terminator) {
			t.Fatalf("sipRequest output missing expected terminator, got:\n%s", req)
		}
		req = strings.TrimSuffix(req, terminator) + "\r\n" + strings.Join(extraHeaders, "\r\n") + terminator
	}
	if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		if wantSubstr != "" && strings.Contains(got.String(), wantSubstr) {
			return got.String()
		}
	}
	return got.String()
}

const knownPeerCfg = `
listen:
  sip: [udp://127.0.0.1:11060]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: in
    from: local-uac
    to: [local-uac]
`

// mustMinimalCfg parses a tiny valid config for tests that only need a
// *Server to exist (e.g. exercising the nil-safe accessors before Run has
// built the registrar/shield) — reuses knownPeerCfg's shape.
func mustMinimalCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(knownPeerCfg))
	if err != nil {
		t.Fatalf("parse minimal config: %v", err)
	}
	return cfg
}

// TestServerAccessorsNilSafe proves the admin-API accessors don't panic on a
// *Server built directly by NewServer (registrar/shield are only assigned in
// Run, which this test never calls).
func TestServerAccessorsNilSafe(t *testing.T) {
	s := NewServer(config.NewStore(mustMinimalCfg(t)), nil, discardLogger())
	// No registrar means no registration gating — the same answer
	// Registrar.IsRegistered gives for a peer it isn't tracking, so the
	// B2BUA's expandTargets gate and the admin view agree either way.
	if !s.IsRegistered("nobody") {
		t.Error("nil registrar → no gating, peer must read as available")
	}
	_ = s.ShieldStats() // must not panic; zero-value stats
}

func TestServerAnswersOptionsFromKnownPeer(t *testing.T) {
	startServer(t, 11060, knownPeerCfg)
	got := roundTrip(t, 11060, "OPTIONS", "opt-known-1", 3*time.Second, "SIP/2.0 200")
	if !strings.Contains(got, "SIP/2.0 200") {
		t.Fatalf("expected 200 OK to OPTIONS, got:\n%s", got)
	}
}

// TestServerInviteFromKnownPeerIsRoutedThenRejectedForNoSDP supersedes the
// M3.1 stub test now that the B2BUA bridge (sig/b2bua.go) owns INVITE and
// (Task 6) actually places the B-leg: knownPeerCfg's route matches any
// number, so a known peer's INVITE is identified and routed successfully,
// reaches dialogSrv.ReadInvite, and only then gets rejected — with 488 Not
// Acceptable Here, since sipRequest builds a bare request with no SDP
// offer to bridge. TestBridgePlacesCallAndBridges (sig/b2bua_test.go) is
// the real happy-path coverage with an actual offer/answer.
func TestServerInviteFromKnownPeerIsRoutedThenRejectedForNoSDP(t *testing.T) {
	startServer(t, 11062, strings.Replace(knownPeerCfg, "11060", "11062", 1))
	got := roundTrip(t, 11062, "INVITE", "inv-known-1", 3*time.Second, "SIP/2.0 488")
	if !strings.Contains(got, "SIP/2.0 488") {
		t.Fatalf("expected 488 (routed, but no SDP offer to bridge), got:\n%s", got)
	}
}

func TestServerDropsUnknownSource(t *testing.T) {
	// allowed_ips excludes loopback → our OPTIONS must be silently dropped.
	cfg := strings.Replace(
		strings.Replace(knownPeerCfg, "11060", "11064", 1),
		"127.0.0.1/32", "10.0.0.0/8", 1)
	startServer(t, 11064, cfg)
	got := roundTrip(t, 11064, "OPTIONS", "opt-unknown-1", 1*time.Second, "")
	if strings.Contains(got, "SIP/2.0") {
		t.Fatalf("unknown source must be dropped, but got a response:\n%s", got)
	}
}

// TestServerDropsUnknownSourceNonOptionsMethod guards the security-plane
// guarantee for methods beyond OPTIONS/INVITE/ACK/BYE: sipgo v1.4.3 routes any
// method without a registered handler (REGISTER, SUBSCRIBE, ...) to its
// default no-route handler, which replies 405 without ever calling
// identify(). An unauthorized source must get silence for every method, not
// just the ones we happen to have explicit handlers for. (Note: BYE now has
// a dedicated onBye handler that gates on identify(), so unidentified BYE is
// dropped by that handler, not the no-route handler.)
func TestServerDropsUnknownSourceNonOptionsMethod(t *testing.T) {
	// allowed_ips excludes loopback → our REGISTER must be silently dropped.
	cfg := strings.Replace(
		strings.Replace(knownPeerCfg, "11060", "11066", 1),
		"127.0.0.1/32", "10.0.0.0/8", 1)
	startServer(t, 11066, cfg)
	got := roundTrip(t, 11066, "REGISTER", "reg-unknown-1", 1*time.Second, "")
	if strings.Contains(got, "SIP/2.0") {
		t.Fatalf("unknown source must be dropped for REGISTER, but got a response:\n%s", got)
	}
}

// TestServerKnownPeerUnhandledMethodGets405 is the positive-path
// counterpart: a known, authorized peer sending a method we don't yet
// implement (REGISTER) still gets a normal 405 Method Not Allowed, since
// it already passed the identify() security check.
func TestServerKnownPeerUnhandledMethodGets405(t *testing.T) {
	cfg := strings.Replace(knownPeerCfg, "11060", "11068", 1)
	startServer(t, 11068, cfg)
	got := roundTrip(t, 11068, "REGISTER", "reg-known-1", 3*time.Second, "SIP/2.0 405")
	if !strings.Contains(got, "SIP/2.0 405") {
		t.Fatalf("expected 405 Method Not Allowed for known peer, got:\n%s", got)
	}
	// audit: P2-TRK-014 — a 405 MUST carry Allow (RFC 3261 §21.4.6).
	if !strings.Contains(got, "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS") {
		t.Fatalf("405 must list the supported methods in Allow, got:\n%s", got)
	}
}

// TestServerAdvertisedIPResolution is Fix 2's regression coverage for
// Server.advertisedIP (now reached via sigIP for signaling headers and
// mediaIP for SDP) — the IP the SBC advertises as its own. Before the fix,
// mediaIP's "auto" fallback used listen.sip[0]'s host unconditionally, so a
// listener bound to 0.0.0.0 (or ::) — the normal way to listen on every
// interface — produced c=0.0.0.0 in SDP (a media blackhole) and
// sip:0.0.0.0:port in Contact (unroutable). The fix: prefer a literal
// public_ip; else skip unspecified listener hosts and use the first
// routable one; else warn once (not per call) and fall back to 127.0.0.1.
// newSrvForResolution parses cfgYAML and builds a *Server with a captured
// log buffer — no listener is bound, so resolution functions can be probed
// without network I/O.
func newSrvForResolution(t *testing.T, cfgYAML string) (*Server, *config.Config, *bytes.Buffer) {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	var logBuf bytes.Buffer
	srv := NewServer(config.NewStore(cfg), nil, slog.New(slog.NewTextHandler(&logBuf, nil)))
	return srv, cfg, &logBuf
}

func TestServerAdvertisedIPResolution(t *testing.T) {
	t.Run("literal public_ip wins even over a routable listener", func(t *testing.T) {
		srv, cfg, _ := newSrvForResolution(t, `
listen:
  sip: [udp://198.51.100.1:5060]
  media: { port_range: 40000-40001, public_ip: 203.0.113.10 }
peers:
  p: { address: 10.0.0.1:5060, allowed_ips: [10.0.0.0/8] }
routes:
  - name: r
    from: p
    to: [p]
`)
		if got := srv.mediaIP(cfg); got.String() != "203.0.113.10" {
			t.Errorf("mediaIP = %s, want 203.0.113.10 (literal public_ip)", got)
		}
	})

	t.Run("auto skips an unspecified listener and picks the routable one", func(t *testing.T) {
		srv, cfg, logBuf := newSrvForResolution(t, `
listen:
  sip: [udp://0.0.0.0:5060, udp://198.51.100.5:5061]
  media: { port_range: 40002-40003, public_ip: auto }
peers:
  p: { address: 10.0.0.1:5060, allowed_ips: [10.0.0.0/8] }
routes:
  - name: r
    from: p
    to: [p]
`)
		if got := srv.sigIP(cfg); got.String() != "198.51.100.5" {
			t.Errorf("sigIP = %s, want 198.51.100.5 (first non-unspecified listen.sip host)", got)
		}
		if strings.Contains(logBuf.String(), "falling back to 127.0.0.1") {
			t.Errorf("unexpected fallback warning when a routable listener exists:\n%s", logBuf.String())
		}
	})

	t.Run("auto with every listener unspecified warns once and falls back to 127.0.0.1", func(t *testing.T) {
		srv, cfg, logBuf := newSrvForResolution(t, `
listen:
  sip: [udp://0.0.0.0:5060, "udp://[::]:5061"]
  media: { port_range: 40004-40005, public_ip: auto }
peers:
  p: { address: 10.0.0.1:5060, allowed_ips: [10.0.0.0/8] }
routes:
  - name: r
    from: p
    to: [p]
`)
		// Call twice: the fallback IP must be stable, and warnAutoIPOnce must
		// gate the warning to a single log line, not one per call.
		for i := 0; i < 2; i++ {
			if got := srv.mediaIP(cfg); got.String() != "127.0.0.1" {
				t.Errorf("call %d: mediaIP = %s, want 127.0.0.1 fallback", i, got)
			}
		}
		if n := strings.Count(logBuf.String(), "falling back to 127.0.0.1"); n != 1 {
			t.Errorf("fallback warning logged %d times across 2 calls, want exactly 1 (warnAutoIPOnce)\nlog:\n%s", n, logBuf.String())
		}
	})
}

// TestServerNATAdvertisedAddresses covers the bind/advertised topology:
// sip.advertised_ip and rtp.advertised_ip override the legacy resolution
// independently — signaling and media can advertise different public
// addresses — while the listeners themselves stay bound to the private
// bind_ip.
func TestServerNATAdvertisedAddresses(t *testing.T) {
	srv, cfg, _ := newSrvForResolution(t, `
sip:
  bind_ip: 10.77.0.2
  bind_port: 16060
  advertised_ip: 198.51.100.7
  advertised_port: 15060
rtp:
  bind_ip: 10.77.0.2
  advertised_ip: 203.0.113.7
peers:
  p: { address: 10.0.0.1:5060, allowed_ips: [10.0.0.0/8] }
routes:
  - name: r
    from: p
    to: [p]
`)
	if got := srv.sigIP(cfg); got.String() != "198.51.100.7" {
		t.Errorf("sigIP = %s, want sip.advertised_ip 198.51.100.7", got)
	}
	if got := srv.mediaIP(cfg); got.String() != "203.0.113.7" {
		t.Errorf("mediaIP = %s, want rtp.advertised_ip 203.0.113.7", got)
	}
	if got := srv.ourSigPort(cfg, "udp"); got != 15060 {
		t.Errorf("ourSigPort = %d, want sip.advertised_port 15060 (never the private bind port 16060)", got)
	}
	ls := cfg.Listeners()
	if len(ls) != 1 || ls[0].Host != "10.77.0.2" || ls[0].Port != 16060 {
		t.Errorf("listeners = %+v, want the private bind 10.77.0.2:16060", ls)
	}
}

// TestServerOurSigPortNo5060Fallback proves the port advertised for our
// signaling always comes from configuration — an empty listener set (only
// constructible directly, without Parse) yields 0, never a hardcoded 5060.
func TestServerOurSigPortNo5060Fallback(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:11170]
  media: { port_range: 40006-40007 }
peers:
  p: { address: 10.0.0.1:5060, allowed_ips: [10.0.0.0/8] }
routes:
  - name: r
    from: p
    to: [p]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	srv := NewServer(config.NewStore(cfg), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := srv.ourSigPort(cfg, "udp"); got != 11170 {
		t.Errorf("ourSigPort(udp) = %d, want configured 11170", got)
	}
	if got := srv.ourSigPort(cfg, "tcp"); got != 11170 {
		t.Errorf("ourSigPort(tcp) = %d, want first-listener fallback 11170", got)
	}
	empty := &config.Config{}
	if got := srv.ourSigPort(empty, "udp"); got != 0 {
		t.Errorf("ourSigPort with no listeners = %d, want 0 (no hardcoded 5060 assumption)", got)
	}
}

func TestServerDropsUnidentifiedBye(t *testing.T) {
	// A BYE from a source that matches no peer must be silently dropped by
	// onBye's identify gate — not routed to the dialog cache. Reuse the
	// unknown-source config (allowed_ips excludes loopback).
	cfg := strings.Replace(
		strings.Replace(knownPeerCfg, "11060", "11078", 1),
		"127.0.0.1/32", "10.0.0.0/8", 1)
	startServer(t, 11078, cfg)
	got := roundTrip(t, 11078, "BYE", "bye-unknown-1", 1*time.Second, "")
	if strings.Contains(got, "SIP/2.0") {
		t.Fatalf("unidentified BYE must be dropped, got a response:\n%s", got)
	}
}

// TestServerByeNoDialogGets481 is the positive-path counterpart to
// TestServerDropsUnidentifiedBye: a BYE from a KNOWN, authorized source
// (loopback, allowed by knownPeerCfg) still isn't silently dropped when it
// carries a To-tag (so it's shaped like an in-dialog request) but matches
// no dialog either dialogSrv or dialogCli actually has — neither this
// server nor any bridge on it ever established the call the tag claims to
// belong to. Per RFC 3261 §15 that must get 481 Call/Transaction Does Not
// Exist, not silence (onBye's identify gate already covers the "silence"
// case for genuinely unauthorized sources — this proves a known peer with
// a stale/bogus dialog reference gets a real, visible error instead).
func TestServerByeNoDialogGets481(t *testing.T) {
	cfg := strings.Replace(knownPeerCfg, "11060", "11079", 1)
	startServer(t, 11079, cfg)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac socket: %v", err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 11079}

	// Same shape as sipRequest's BYE, but the To header carries a tag —
	// exactly the re-INVITE test's technique (TestBridgeRejectsReInvite) for
	// making a standalone request look in-dialog without an established
	// call behind it.
	req := strings.Replace(
		sipRequest("BYE", "11079", local, "bye-nodialog-1"),
		"To: <sip:sbc@127.0.0.1>",
		"To: <sip:sbc@127.0.0.1>;tag=bye-nodialog-tag",
		1,
	)
	if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatalf("write bye: %v", err)
	}

	var got strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		if strings.Contains(got.String(), "SIP/2.0 481") {
			break
		}
	}
	if !strings.Contains(got.String(), "SIP/2.0 481") {
		t.Fatalf("BYE with no dialog must get 481, got:\n%s", got.String())
	}
}

// KillCall must not read call state outside the lock: endCall writes
// c.state while an admin kick may be running. s.calls only ever holds
// bridged entries, so the lookup alone is the whole check. Under -race
// this fails on any unsynchronised read.
func TestKillCallRacesNaturalEnd(t *testing.T) {
	const n = 200
	s := &Server{}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		id := "call-" + strconv.Itoa(i)
		_, cancel := context.WithCancel(context.Background())
		c := &call{id: id, cancel: cancel}
		s.registerCall(c)

		wg.Add(2)
		go func() { defer wg.Done(); s.endCall(c) }()
		go func() { defer wg.Done(); s.KillCall(id) }()
	}
	wg.Wait()
	if got := s.ActiveCalls(); got != 0 {
		t.Errorf("ActiveCalls = %d after every call ended, want 0", got)
	}
}
