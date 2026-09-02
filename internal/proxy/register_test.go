package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// client is a test SIP endpoint: its own user agent, listener and client,
// so it receives responses (and inbound requests) exactly as a real phone
// or browser would.
type client struct {
	t         *testing.T
	ua        *sipgo.UserAgent
	srv       *sipgo.Server
	cli       *sipgo.Client
	transport string
	local     string // host:port we listen on ("" for ws, which is outbound)

	inbound chan *sip.Request

	// answerMu guards answer: the test goroutine installs it while sipgo
	// handler goroutines may already be reading it.
	answerMu sync.Mutex
	answer   func(req *sip.Request, tx sip.ServerTransaction)

	cancel context.CancelFunc
}

// newUDPClient starts a phone speaking SIP over UDP from a real local
// socket, so the proxy's NAT-style "respond to the source" path is
// exercised for real.
func newUDPClient(t *testing.T) *client {
	t.Helper()
	c := newClientBase(t, "udp")
	port := freePort(t)
	c.local = fmt.Sprintf("127.0.0.1:%d", port)
	addr, err := net.ResolveUDPAddr("udp", c.local)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	prev := c.cancel
	c.cancel = func() { cancel(); prev() }
	go func() { <-ctx.Done(); conn.Close() }()
	go func() { _ = c.srv.TransportLayer().ServeUDP(conn) }()
	return c
}

// newWSClient stands in for sip.js: it opens a WebSocket to the proxy and
// does everything over that one connection, never listening itself.
func newWSClient(t *testing.T) *client {
	t.Helper()
	return newClientBase(t, "ws")
}

func newClientBase(t *testing.T, transport string) *client {
	t.Helper()
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, ua: ua, srv: srv, cli: cli, transport: transport,
		inbound: make(chan *sip.Request, 8)}
	handler := func(req *sip.Request, tx sip.ServerTransaction) {
		select {
		case c.inbound <- req.Clone():
		default:
		}
		c.answerMu.Lock()
		answer := c.answer
		c.answerMu.Unlock()
		if answer != nil {
			answer(req, tx)
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
	srv.OnInvite(handler)
	srv.OnBye(handler)
	srv.OnOptions(handler)
	srv.OnNoRoute(handler)
	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		select {
		case c.inbound <- req.Clone():
		default:
		}
	})
	c.cancel = func() { _ = cli.Close(); _ = ua.Close() }
	t.Cleanup(func() { c.cancel() })
	return c
}

// setAnswer installs the handler for inbound requests.
func (c *client) setAnswer(f func(req *sip.Request, tx sip.ServerTransaction)) {
	c.answerMu.Lock()
	c.answer = f
	c.answerMu.Unlock()
}

// contactURI is what this client puts in its Contact header. A WebSocket
// client writes an unreachable ".invalid" host, exactly as sip.js does —
// which is the whole reason the proxy must rewrite it before FreeSWITCH
// ever sees it.
func (c *client) contactURI(user string) sip.Uri {
	if c.transport == "ws" {
		params := sip.NewParams()
		params.Add("transport", "ws")
		return sip.Uri{User: user, Host: "abcd1234.invalid", UriParams: params}
	}
	host, portStr, _ := net.SplitHostPort(c.local)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return sip.Uri{User: user, Host: host, Port: port}
}

// do sends one request to dest and returns the final response.
func (c *client) do(t *testing.T, req *sip.Request, dest string) *sip.Response {
	t.Helper()
	req.SetTransport(strings.ToUpper(c.transport))
	req.SetDestination(dest)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := c.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("send %s: %v", req.Method, err)
	}
	defer tx.Terminate()
	for {
		select {
		case res, ok := <-tx.Responses():
			if !ok {
				t.Fatalf("%s: transaction closed with no final response", req.Method)
			}
			if res.StatusCode >= 200 {
				return res
			}
		case <-tx.Done():
			t.Fatalf("%s: %v", req.Method, tx.Err())
		case <-ctx.Done():
			t.Fatalf("%s: timed out", req.Method)
		}
	}
}

// buildRegister assembles a REGISTER the way a phone does.
func (c *client) buildRegister(user, domain string, expires int, auth string) *sip.Request {
	req := sip.NewRequest(sip.REGISTER, sip.Uri{Host: domain})
	from := &sip.FromHeader{Address: sip.Uri{User: user, Host: domain}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: user, Host: domain}, Params: sip.NewParams()})
	callID := sip.CallIDHeader("reg-" + user + "-" + c.transport)
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.REGISTER})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: c.contactURI(user)})
	req.AppendHeader(sip.NewHeader("Expires", fmt.Sprintf("%d", expires)))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0",
		Transport: strings.ToUpper(c.transport), Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	if c.transport == "udp" {
		via.Params.Add("rport", "")
	}
	req.PrependHeader(via)
	if auth != "" {
		req.AppendHeader(sip.NewHeader("Authorization", auth))
	}
	return req
}

// TestCaseA_UDPRegistration is acceptance criterion 1: a SIP/UDP phone
// registers through FreeSBC to FreeSWITCH, digest and all.
func TestCaseA_UDPRegistration(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	runRegistrationCase(t, h, phone, h.publicUDP)
}

// TestCaseC_WebSocketRegistration is acceptance criterion 2: the same
// exchange from sip.js over a WebSocket, reaching FreeSWITCH over UDP.
func TestCaseC_WebSocketRegistration(t *testing.T) {
	h := startHarness(t, false)
	browser := newWSClient(t)
	runRegistrationCase(t, h, browser, h.publicWS)
}

// runRegistrationCase drives the two-step digest registration and asserts
// on both what the phone saw and what FreeSWITCH saw.
func runRegistrationCase(t *testing.T, h *harness, c *client, dest string) {
	t.Helper()

	// --- step 1: unauthenticated REGISTER must come back challenged ---
	res := c.do(t, c.buildRegister("1001", "example.com", 600, ""), dest)
	if res.StatusCode != 401 {
		t.Fatalf("first REGISTER: got %d, want 401", res.StatusCode)
	}
	// The challenge must reach the phone byte-for-byte: FreeSBC is not the
	// registrar and must not touch the realm or the nonce.
	chal := res.GetHeader("WWW-Authenticate")
	if chal == nil {
		t.Fatal("challenge lost in transit")
	}
	if !strings.Contains(chal.Value(), `realm="example.com"`) || !strings.Contains(chal.Value(), "abc123nonce") {
		t.Fatalf("challenge altered: %s", chal.Value())
	}

	// --- step 2: the credentialed REGISTER must be accepted ---
	const authz = `Digest username="1001", realm="example.com", nonce="abc123nonce", uri="sip:example.com", response="deadbeefdeadbeefdeadbeefdeadbeef", algorithm=MD5`
	res = c.do(t, c.buildRegister("1001", "example.com", 600, authz), dest)
	if res.StatusCode != 200 {
		t.Fatalf("authenticated REGISTER: got %d, want 200", res.StatusCode)
	}

	// The credential must have crossed FreeSBC untouched — FreeSBC never
	// computes, rewrites or challenges digest itself.
	regs := h.fs.waitFor(sip.REGISTER, 2, 3*time.Second)
	if len(regs) < 2 {
		t.Fatalf("FreeSWITCH saw %d REGISTERs, want 2", len(regs))
	}
	upstreamAuth := regs[1].GetHeader("Authorization")
	if upstreamAuth == nil || upstreamAuth.Value() != authz {
		t.Fatalf("Authorization altered in transit:\n got %v\nwant %s", upstreamAuth, authz)
	}
	// The Request-URI must survive too: the digest response was computed
	// over it, so rewriting it would break every authenticated REGISTER.
	if got := regs[1].Recipient.String(); !strings.Contains(got, "example.com") {
		t.Errorf("Request-URI rewritten to %q; the digest was computed over the original", got)
	}

	// --- what FreeSWITCH stored ---
	contacts := h.fs.contacts()
	if len(contacts) == 0 {
		t.Fatal("FreeSWITCH stored no contact")
	}
	stored := contacts[0]
	if !strings.Contains(stored, h.srv.topo.private.advIP.String()) {
		t.Errorf("stored contact %q does not point at the SBC's private address", stored)
	}
	if !strings.Contains(stored, contactTokenParam+"=") {
		t.Errorf("stored contact %q carries no binding token", stored)
	}
	if strings.Contains(stored, "transport=ws") {
		t.Errorf("stored contact %q leaks the client's WebSocket transport to FreeSWITCH", stored)
	}
	if strings.Contains(stored, ".invalid") {
		t.Errorf("stored contact %q leaks the browser's unreachable host", stored)
	}

	// --- what the phone saw back ---
	// sip.js compares the returned Contact against the one it sent and
	// treats a mismatch as a failed registration.
	back, ok := contactURI(res)
	if !ok {
		t.Fatal("200 OK carried no Contact")
	}
	want := c.contactURI("1001")
	if back.Host != want.Host || back.User != want.User {
		t.Errorf("Contact not restored: got %s, want %s", back.String(), want.String())
	}
	if strings.Contains(back.String(), contactTokenParam+"=") {
		t.Errorf("binding token leaked to the client: %s", back.String())
	}

	// --- the binding FreeSBC recorded ---
	bindings := h.srv.loc.ByAOR("1001@example.com")
	if len(bindings) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bindings))
	}
	b := bindings[0]
	if b.Transport != c.transport {
		t.Errorf("binding transport = %q, want %q", b.Transport, c.transport)
	}
	// The registrar granted 120s though the phone asked for 600: the
	// binding must follow the registrar, not the request.
	if d := time.Until(b.ExpiresAt); d > 130*time.Second || d < 110*time.Second {
		t.Errorf("binding expiry %v does not match the registrar's 120s grant", d)
	}
	// The source is the real transport address, never the Contact host.
	if !b.Source.IsValid() {
		t.Error("binding recorded no source address")
	}
	if c.transport == "ws" && strings.Contains(b.Contact, "127.0.0.1") {
		t.Error("WebSocket binding recorded a routable contact where the client wrote .invalid")
	}
}

// A refresh must reuse the token, so the contact FreeSWITCH already stored
// keeps resolving.
func TestRegistrationRefreshKeepsBinding(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()

	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("first REGISTER: %d", res.StatusCode)
	}
	first := h.srv.loc.ByAOR("1001@example.com")
	if len(first) != 1 {
		t.Fatalf("bindings = %d", len(first))
	}
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("refresh REGISTER: %d", res.StatusCode)
	}
	second := h.srv.loc.ByAOR("1001@example.com")
	if len(second) != 1 {
		t.Fatalf("refresh created %d bindings, want 1", len(second))
	}
	if second[0].Token != first[0].Token {
		t.Error("refresh changed the token FreeSWITCH has stored")
	}
	// FreeSWITCH must have been shown the same contact both times.
	contacts := h.fs.contacts()
	if len(contacts) != 2 || contacts[0] != contacts[1] {
		t.Errorf("contact changed across refresh: %v", contacts)
	}
}

// Expires: 0 removes the binding.
func TestUnregisterRemovesBinding(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()

	phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicUDP)
	if h.srv.loc.Count() != 1 {
		t.Fatalf("bindings = %d after register", h.srv.loc.Count())
	}
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 0, ""), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("un-REGISTER: %d", res.StatusCode)
	}
	if h.srv.loc.Count() != 0 {
		t.Errorf("bindings = %d after un-REGISTER, want 0", h.srv.loc.Count())
	}
}

// A REGISTER carrying several Contacts must reach the registrar with ONLY
// the SBC's rewritten one. Leaving the client's own contacts alongside it
// would hand FreeSWITCH addresses that bypass the SBC entirely — sipgo's
// RemoveHeader deletes only the first match, so this needs an explicit
// sweep (see removeAll).
func TestMultipleContactsAreAllReplaced(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()

	req := phone.buildRegister("1001", "example.com", 600, "")
	// A second device's contact, as a multi-contact REGISTER carries.
	req.AppendHeader(&sip.ContactHeader{
		Address: sip.Uri{User: "1001", Host: "198.51.100.77", Port: 5062},
	})
	if res := phone.do(t, req, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}

	regs := h.fs.waitFor(sip.REGISTER, 1, 3*time.Second)
	if len(regs) == 0 {
		t.Fatal("FreeSWITCH saw no REGISTER")
	}
	contacts := regs[0].GetHeaders("Contact")
	if len(contacts) != 1 {
		t.Fatalf("FreeSWITCH saw %d Contacts, want exactly 1", len(contacts))
	}
	if got := contacts[0].Value(); strings.Contains(got, "198.51.100.77") {
		t.Errorf("the client's own contact leaked upstream: %s", got)
	}
	if !strings.Contains(contacts[0].Value(), contactTokenParam+"=") {
		t.Errorf("the surviving Contact is not the SBC's: %s", contacts[0].Value())
	}
}

// A WebSocket registration is reachable only through its own connection.
// When that connection closes, the binding must go with it — otherwise
// FreeSBC would keep accepting inbound calls it has no way to deliver.
func TestWebSocketCloseDropsBindings(t *testing.T) {
	h := startHarness(t, false)
	browser := newWSClient(t)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()

	if res := browser.do(t, browser.buildRegister("1001", "example.com", 600, ""), h.publicWS); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	if h.srv.loc.Count() != 1 {
		t.Fatalf("bindings = %d after register", h.srv.loc.Count())
	}

	// Close the browser's user agent, which closes its WebSocket.
	browser.cancel()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.loc.Count() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("binding survived the WebSocket close: %d still registered", h.srv.loc.Count())
}
