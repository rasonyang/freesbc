package edge

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// silenceWait is how long a test waits to conclude that no response is
// coming. sipgo would send "100 Trying" for an INVITE after Timer_1xx
// (200 ms) had the transaction not been terminated, and a relayed final
// takes a loopback round trip, so a second is ample.
const silenceWait = time.Second

// expectSilence sends req from c to dest as a client transaction and fails
// the test if ANY response (provisional or final) arrives within
// silenceWait. Over UDP sipgo retransmits the request meanwhile, so the
// retransmissions are exercised too.
func expectSilence(t *testing.T, c *client, req *sip.Request, dest string) {
	t.Helper()
	req.SetTransport(strings.ToUpper(c.transport))
	req.SetDestination(dest)
	ctx, cancel := context.WithTimeout(context.Background(), silenceWait)
	defer cancel()
	tx, err := c.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("send %s: %v", req.Method, err)
	}
	defer tx.Terminate()
	select {
	case res := <-tx.Responses():
		t.Fatalf("%s: got %d %s, want no response at all", req.Method, res.StatusCode, res.Reason)
	case <-ctx.Done():
	}
}

// holdConnection opens c's stream connection to dest up front and returns
// its local address. A request whose Laddr names it reuses that connection,
// as sip.js keeps its one WebSocket for the whole session. Without this the
// sipgo test client dials a fresh connection per request over wss (sipgo
// v1.6.0's TransportWSS.CreateConnection pools the connection under
// swapped laddr/raddr keys, so a lookup by remote address never hits), and
// each request arrives from a new source port — which admission rightly
// treats as a different, unregistered client.
func holdConnection(t *testing.T, c *client, dest string) sip.Addr {
	t.Helper()
	req := c.buildRegister("hold", "example.com", 0, "")
	req.SetTransport(strings.ToUpper(c.transport))
	req.SetDestination(dest)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.ua.TransportLayer().ClientRequestConnection(ctx, req)
	if err != nil {
		t.Fatalf("open %s connection to %s: %v", c.transport, dest, err)
	}
	ap := netip.MustParseAddrPort(conn.LocalAddr().String())
	return sip.Addr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
}

// admissionDrops reads one admission drop counter.
func admissionDrops(h *harness, r dropReason) uint64 {
	return h.srv.metrics.Snapshot().AdmissionDrops[r.String()]
}

// An out-of-dialog INVITE from a public source that is not registered, not a
// carrier and not FreeSWITCH gets no response at all — not even the
// "100 Trying" sipgo sends on its own after 200 ms — and never reaches
// FreeSWITCH. Checked on a raw socket, so nothing a client stack does can
// hide a stray datagram.
func TestAdmissionUnregisteredUDPInviteDropped(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	conn := auditUDP(t)
	raw := &client{transport: "udp", local: conn.LocalAddr().String()}
	invite := raw.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000))
	pub, err := net.ResolveUDPAddr("udp", h.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	// Twice: the second is what a UDP retransmission looks like, and must
	// be dropped the same way (a fresh server transaction each time).
	for i := 0; i < 2; i++ {
		if _, err := conn.WriteToUDP([]byte(invite.String()), pub); err != nil {
			t.Fatal(err)
		}
		// Past Timer_1xx, so the first transaction is long gone when the
		// second copy arrives.
		time.Sleep(300 * time.Millisecond)
	}
	if auditRecvUntil(conn, silenceWait, func([]byte) bool { return true }) {
		t.Fatal("the proxy answered an unadmitted INVITE; want silence")
	}
	if got := h.fs.received(sip.INVITE); len(got) != 0 {
		t.Fatalf("FreeSWITCH saw %d INVITEs from an unadmitted source", len(got))
	}
	if n := admissionDrops(h, dropInviteNotAdmitted); n != 2 {
		t.Errorf("invite_not_admitted drops = %d, want 2", n)
	}
	if n := h.srv.dialogs.count(); n != 0 {
		t.Errorf("dialogs = %d after a dropped INVITE, want 0", n)
	}
}

// A phone that registered over UDP places calls from the transport address
// its binding records, and they proceed. Another socket on the same IP does
// not inherit the registration.
func TestAdmissionRegisteredUDPClientCallProceeds(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")

	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000)), h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE from a registered phone: got %d, want 200", res.StatusCode)
	}
	if got := h.fs.waitFor(sip.INVITE, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs, want 1", len(got))
	}
	if n := admissionDrops(h, dropInviteNotAdmitted); n != 0 {
		t.Errorf("invite_not_admitted drops = %d, want 0", n)
	}

	other := newUDPClient(t)
	expectSilence(t, other, other.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4002)), h.publicUDP)
	if got := h.fs.received(sip.INVITE); len(got) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs, want only the registered phone's", len(got))
	}
}

// An INVITE from a edge.carrier_sources prefix proceeds without any
// registration.
func TestAdmissionCarrierSourceProceeds(t *testing.T) {
	h := startHarnessFull(t, false, false, "127.0.0.0/8")
	if got := h.srv.carriers.snapshot().sourcesString(); got != "127.0.0.0/8" {
		t.Errorf("carrier sources = %q, want 127.0.0.0/8", got)
	}
	carrier := newUDPClient(t)
	res := carrier.do(t, carrier.buildInvite("+15551230000", "1001", "example.com", phoneOfferSDP(4000)), h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("carrier INVITE: got %d, want 200", res.StatusCode)
	}
}

// A browser that registered over WSS calls over the same connection, and the
// call proceeds; a second, unregistered WSS connection is dropped silently.
func TestAdmissionWSSBrowserRegisterAndCall(t *testing.T) {
	h := startHarnessStrict(t, true, true)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()

	browser := newWSSClient(t)
	laddr := holdConnection(t, browser, h.publicWSS)
	reg := browser.buildRegister("1001", "example.com", 600, "")
	reg.Laddr = laddr
	if res := browser.do(t, reg, h.publicWSS); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	invite := browser.buildInvite("1001", "2002", "example.com", browserOfferSDP(51234))
	invite.Laddr = laddr
	if res := browser.do(t, invite, h.publicWSS); res.StatusCode != 200 {
		t.Fatalf("INVITE from a registered browser: got %d, want 200", res.StatusCode)
	}
	if got := h.fs.waitFor(sip.INVITE, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs, want 1", len(got))
	}

	stranger := newWSSClient(t)
	expectSilence(t, stranger, stranger.buildInvite("1002", "2002", "example.com", browserOfferSDP(51236)), h.publicWSS)
	if got := h.fs.received(sip.INVITE); len(got) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs, want only the registered browser's", len(got))
	}
}

// The same over plain WS, through the whole call: INVITE, ACK, BYE.
func TestAdmissionWSBrowserRegisterAndCall(t *testing.T) {
	h := startHarnessStrict(t, true, false)
	browser := newWSClient(t)
	holdConnection(t, browser, h.publicWS) // ws reuses by remote address
	registerOver(t, h, browser, h.publicWS, "1001")

	invite := browser.buildInvite("1001", "2002", "example.com", browserOfferSDP(51234))
	res := browser.do(t, invite, h.publicWS)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE from a registered browser: got %d, want 200", res.StatusCode)
	}
	sendAck(t, browser, invite, res, h.publicWS)
	if r := browser.do(t, buildBye(browser, invite, res), h.publicWS); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
	if n := admissionDrops(h, dropInviteNotAdmitted); n != 0 {
		t.Errorf("invite_not_admitted drops = %d, want 0", n)
	}
}

// After enumMaxAORs distinct AoRs have been rejected 403 by the registrar,
// the source's next REGISTER is dropped silently and never reaches
// FreeSWITCH. Digest challenges (401) do not count.
func TestAdmissionRegisterEnumerationLimit(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	scanner := newUDPClient(t)

	// Challenges first, for more distinct AoRs than the limit: none count.
	for i := 0; i < enumMaxAORs+2; i++ {
		res := scanner.do(t, scanner.buildRegister(fmt.Sprintf("c%d", i), "example.com", 600, ""), h.publicUDP)
		if res.StatusCode != 401 {
			t.Fatalf("challenge %d: got %d, want 401", i, res.StatusCode)
		}
	}

	h.fs.mu.Lock()
	h.fs.registerStatus = 403
	h.fs.mu.Unlock()
	for i := 0; i < enumMaxAORs; i++ {
		res := scanner.do(t, scanner.buildRegister(fmt.Sprintf("u%d", i), "example.com", 600, ""), h.publicUDP)
		if res.StatusCode != 403 {
			t.Fatalf("rejection %d: got %d, want 403 (the limit fired early)", i, res.StatusCode)
		}
	}
	upstreamBefore := len(h.fs.received(sip.REGISTER))
	if want := 2*enumMaxAORs + 2; upstreamBefore != want {
		t.Fatalf("FreeSWITCH saw %d REGISTERs, want %d", upstreamBefore, want)
	}

	expectSilence(t, scanner, scanner.buildRegister("u-next", "example.com", 600, ""), h.publicUDP)
	if got := len(h.fs.received(sip.REGISTER)); got != upstreamBefore {
		t.Fatalf("FreeSWITCH saw %d REGISTERs after the limit, want %d", got, upstreamBefore)
	}
	if n := admissionDrops(h, dropRegisterEnumeration); n == 0 {
		t.Error("register_enumeration drops = 0")
	}
}

// TestAdmissionRegisterEnumerationRecordedBeforeRelay pins the order of the
// 403 and the limiter (#93). The limiter's clock is read once by blocked()
// and once by rejected(); the test gates the second read, which is the
// 10th rejection being recorded. The client must not see that 403 while the
// recording is still pending: with the old order (relay, then record) the
// 403 arrives during the gate and expectSilence fails.
func TestAdmissionRegisterEnumerationRecordedBeforeRelay(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	scanner := newUDPClient(t)
	src := netip.MustParseAddr("127.0.0.1")

	for i := 0; i < enumMaxAORs-1; i++ {
		h.srv.enumLimit.rejected(src, fmt.Sprintf("seed%d@example.com", i))
	}
	h.fs.mu.Lock()
	h.fs.registerStatus = 403
	h.fs.mu.Unlock()

	reached, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	l := h.srv.enumLimit
	l.mu.Lock() // the network gives the race detector no edge to the handler
	real := l.now
	l.now = func() time.Time {
		if calls.Add(1) == 2 { // blocked() was call 1; this is rejected()
			close(reached)
			<-release
		}
		return real()
	}
	l.mu.Unlock()

	// The 403 is held back while the rejection is unrecorded.
	expectSilence(t, scanner, scanner.buildRegister("tenth", "example.com", 600, ""), h.publicUDP)
	select {
	case <-reached:
	default:
		t.Fatal("rejected() was never reached")
	}
	close(release)

	deadline := time.Now().Add(5 * time.Second)
	for !h.srv.enumLimit.blocked(src) {
		if time.Now().After(deadline) {
			t.Fatal("the 10th rejection was never recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	expectSilence(t, scanner, scanner.buildRegister("u-next", "example.com", 600, ""), h.publicUDP)
}

func TestEnumLimiterCountsDistinctAORsPerWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newEnumLimiter()
	l.now = func() time.Time { return now }
	ip := netip.MustParseAddr("198.51.100.7")

	for i := 0; i < enumMaxAORs-1; i++ {
		l.rejected(ip, fmt.Sprintf("u%d@example.com", i))
		l.rejected(ip, fmt.Sprintf("u%d@example.com", i)) // a repeat is not distinct
	}
	if l.blocked(ip) {
		t.Fatal("blocked below the limit")
	}
	if !l.rejected(ip, "last@example.com") {
		t.Error("rejected did not report reaching the limit")
	}
	if !l.blocked(ip) {
		t.Fatal("not blocked at the limit")
	}
	if l.blocked(netip.MustParseAddr("198.51.100.8")) {
		t.Error("another IPv4 source is blocked")
	}
	now = now.Add(enumWindow)
	if l.blocked(ip) {
		t.Error("still blocked after the window")
	}
	// A new window starts from zero.
	l.rejected(ip, "fresh@example.com")
	if l.blocked(ip) {
		t.Error("blocked after one rejection in a new window")
	}
}

// IPv6 sources are keyed by their /64, like the shield's rate limiter.
func TestEnumLimiterKeysIPv6By64(t *testing.T) {
	l := newEnumLimiter()
	for i := 0; i < enumMaxAORs; i++ {
		l.rejected(netip.MustParseAddr(fmt.Sprintf("2001:db8:1:2::%x", i+1)), fmt.Sprintf("u%d@example.com", i))
	}
	if !l.blocked(netip.MustParseAddr("2001:db8:1:2:ffff::1")) {
		t.Error("the /64 is not blocked")
	}
	if l.blocked(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Error("a different /64 is blocked")
	}
}

// Past the source cap the least recently rejected source is evicted; a new
// source is always tracked.
func TestEnumLimiterEvictsOldestAtCap(t *testing.T) {
	l := newEnumLimiter()
	l.max = 3
	a := netip.MustParseAddr("198.51.100.1")
	for i := 0; i < enumMaxAORs; i++ {
		l.rejected(a, fmt.Sprintf("u%d@example.com", i))
	}
	if !l.blocked(a) {
		t.Fatal("a not blocked")
	}
	for i := 2; i <= 4; i++ {
		l.rejected(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)), "x@example.com")
	}
	if len(l.entries) != 3 || l.lru.Len() != 3 {
		t.Fatalf("entries = %d/%d, want 3", len(l.entries), l.lru.Len())
	}
	if l.blocked(a) {
		t.Error("the oldest source was not evicted")
	}
	if _, ok := l.entries[enumKey(netip.MustParseAddr("198.51.100.4"))]; !ok {
		t.Error("the newest source is not tracked")
	}
}

func TestCountsAsEnumeration(t *testing.T) {
	for code, want := range map[int]bool{403: true, 404: true, 401: false, 407: false, 200: false, 500: false, 503: false} {
		if got := countsAsEnumeration(code); got != want {
			t.Errorf("countsAsEnumeration(%d) = %v, want %v", code, got, want)
		}
	}
}

// The WARN-once set is bounded: past its cap it forgets the oldest entry.
func TestWarnOnceIsBounded(t *testing.T) {
	w := newWarnOnce(2)
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	if !w.first(dropInviteNotAdmitted, a) || w.first(dropInviteNotAdmitted, a) {
		t.Fatal("first/repeat for a")
	}
	if !w.first(dropRegisterEnumeration, a) {
		t.Error("the reason is part of the key")
	}
	if !w.first(dropInviteNotAdmitted, b) || !w.first(dropInviteNotAdmitted, c) {
		t.Fatal("b, c not first")
	}
	if len(w.seen) != 2 {
		t.Fatalf("seen = %d, want the cap 2", len(w.seen))
	}
}
