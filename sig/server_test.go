package sig

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/config"
	"github.com/freesbc/freesbc/media"
)

// startServer boots a sig.Server on the given UDP port with the given
// config YAML and returns once it is accepting packets. The server stops
// when the test ends. The returned *Server lets tests reach into
// package-private state (registry, pool) for assertions.
func startServer(t *testing.T, port int, cfgYAML string) *Server {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore(cfg)
	pool := media.NewPool(store)
	srv := NewServer(store, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx) }()
	// Wait until the UDP port answers (bind completed).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
			time.Sleep(100 * time.Millisecond)
			return srv
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not start")
	return nil
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
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort}
	req := sipRequest(method, fmt.Sprintf("%d", targetPort), local, callID)
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
  sip: [udp://127.0.0.1:45060]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: in
    from: local-uac
    to: [local-uac]
`

func TestServerAnswersOptionsFromKnownPeer(t *testing.T) {
	startServer(t, 45060, knownPeerCfg)
	got := roundTrip(t, 45060, "OPTIONS", "opt-known-1", 3*time.Second, "SIP/2.0 200")
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
	startServer(t, 45062, strings.Replace(knownPeerCfg, "45060", "45062", 1))
	got := roundTrip(t, 45062, "INVITE", "inv-known-1", 3*time.Second, "SIP/2.0 488")
	if !strings.Contains(got, "SIP/2.0 488") {
		t.Fatalf("expected 488 (routed, but no SDP offer to bridge), got:\n%s", got)
	}
}

func TestServerDropsUnknownSource(t *testing.T) {
	// allowed_ips excludes loopback → our OPTIONS must be silently dropped.
	cfg := strings.Replace(
		strings.Replace(knownPeerCfg, "45060", "45064", 1),
		"127.0.0.1/32", "10.0.0.0/8", 1)
	startServer(t, 45064, cfg)
	got := roundTrip(t, 45064, "OPTIONS", "opt-unknown-1", 1*time.Second, "")
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
		strings.Replace(knownPeerCfg, "45060", "45066", 1),
		"127.0.0.1/32", "10.0.0.0/8", 1)
	startServer(t, 45066, cfg)
	got := roundTrip(t, 45066, "REGISTER", "reg-unknown-1", 1*time.Second, "")
	if strings.Contains(got, "SIP/2.0") {
		t.Fatalf("unknown source must be dropped for REGISTER, but got a response:\n%s", got)
	}
}

// TestServerKnownPeerUnhandledMethodGets405 is the positive-path
// counterpart: a known, authorized peer sending a method we don't yet
// implement (REGISTER) still gets a normal 405 Method Not Allowed, since
// it already passed the identify() security check.
func TestServerKnownPeerUnhandledMethodGets405(t *testing.T) {
	cfg := strings.Replace(knownPeerCfg, "45060", "45068", 1)
	startServer(t, 45068, cfg)
	got := roundTrip(t, 45068, "REGISTER", "reg-known-1", 3*time.Second, "SIP/2.0 405")
	if !strings.Contains(got, "SIP/2.0 405") {
		t.Fatalf("expected 405 Method Not Allowed for known peer, got:\n%s", got)
	}
}

func TestServerDropsUnidentifiedBye(t *testing.T) {
	// A BYE from a source that matches no peer must be silently dropped by
	// onBye's identify gate — not routed to the dialog cache. Reuse the
	// unknown-source config (allowed_ips excludes loopback).
	cfg := strings.Replace(
		strings.Replace(knownPeerCfg, "45060", "45078", 1),
		"127.0.0.1/32", "10.0.0.0/8", 1)
	startServer(t, 45078, cfg)
	got := roundTrip(t, 45078, "BYE", "bye-unknown-1", 1*time.Second, "")
	if strings.Contains(got, "SIP/2.0") {
		t.Fatalf("unidentified BYE must be dropped, got a response:\n%s", got)
	}
}
