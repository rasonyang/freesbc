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
// when the test ends.
func startServer(t *testing.T, port int, cfgYAML string) {
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
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not start")
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

// TestServerInviteFromKnownPeerIsRoutedThenRejected supersedes the M3.1
// stub test now that the B2BUA bridge (sig/b2bua.go) owns INVITE:
// knownPeerCfg's route matches any number, so a known peer's INVITE is
// identified and routed successfully, but still gets 404 because the
// B-leg isn't implemented until Task 6.
func TestServerInviteFromKnownPeerIsRoutedThenRejected(t *testing.T) {
	startServer(t, 45062, strings.Replace(knownPeerCfg, "45060", "45062", 1))
	got := roundTrip(t, 45062, "INVITE", "inv-known-1", 3*time.Second, "SIP/2.0 404")
	if !strings.Contains(got, "SIP/2.0 404") {
		t.Fatalf("expected 404 (no B-leg yet), got:\n%s", got)
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
// guarantee for methods beyond OPTIONS/INVITE/ACK: sipgo v1.4.3 routes any
// method without a registered handler (REGISTER, BYE, SUBSCRIBE, ...) to its
// default no-route handler, which replies 405 without ever calling
// identify(). An unauthorized source must get silence for every method, not
// just the ones we happen to have explicit handlers for.
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
