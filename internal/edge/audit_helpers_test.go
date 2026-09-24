package edge

// Helpers shared by the audit_*_test.go files (docs/audit, Phase 3). They
// reuse the package's existing harness and add only what the audit tests
// need to observe: pool usage, the dialog table, owned goroutines, and a
// fake switch whose BYE handler a test chooses.

import (
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// auditReplaceConfig publishes a modified copy of the harness's current
// snapshot, the way config.Watch does on a hot reload. Every field the audit
// tests change is a value type, so a shallow copy never mutates the old
// snapshot.
func auditReplaceConfig(h *harness, mut func(c *config.Config)) {
	c := *h.store.Current()
	mut(&c)
	h.store.Replace(&c)
}

// auditDialogEntries is the number of records in the dialog table in any
// state (ActiveCalls counts confirmed ones only).
func auditDialogEntries(h *harness) int {
	h.srv.dialogs.mu.Lock()
	defer h.srv.dialogs.mu.Unlock()
	return len(h.srv.dialogs.byCallID)
}

// auditOwnedGoroutines counts goroutines that belong to the code under test:
// stacks with an edge, media or pion frame and no frame from a _test.go file
// (the harness, the fake switch and the test clients are excluded). sipgo's
// own parked transaction goroutines (Timer J/K) carry no such frame and are
// not counted.
func auditOwnedGoroutines() (int, string) {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	count := 0
	var dump strings.Builder
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		owned := strings.Contains(g, "freesbc/internal/edge.") ||
			strings.Contains(g, "freesbc/internal/media.") ||
			strings.Contains(g, "github.com/pion/")
		if !owned || strings.Contains(g, "_test.go") {
			continue
		}
		count++
		dump.WriteString(g)
		dump.WriteString("\n\n")
	}
	return count, dump.String()
}

// auditWaitOwnedGoroutines retries until the owned-goroutine count is back to
// baseline or d expires, and reports the stacks left over.
func auditWaitOwnedGoroutines(t *testing.T, label string, baseline int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		n, dump := auditOwnedGoroutines()
		if n <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%s: owned goroutines %d > baseline %d after %v:\n%s", label, n, baseline, d, dump)
			return
		}
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
}

// auditWaitBalanced waits (bounded) for both media pools to be empty and the
// dialog table to hold nothing, then reports what is left.
func auditWaitBalanced(t *testing.T, h *harness, label string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		pub, _ := h.srv.pubPool.Stats()
		priv, _ := h.srv.privPool.Stats()
		entries := auditDialogEntries(h)
		if pub == 0 && priv == 0 && entries == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%s: not balanced after %v: public ports in use=%d private=%d dialog records=%d confirmed=%d",
				label, d, pub, priv, entries, h.srv.ActiveCalls())
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// auditPhoneCall places a phone→upstream call and ACKs it. The returned
// socket is the phone's RTP socket, advertised in its offer.
func auditPhoneCall(t *testing.T, h *harness, phone *client) (*sip.Request, *sip.Response, *net.UDPConn) {
	t.Helper()
	rtp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rtp.Close() })
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(rtp.LocalAddr().(*net.UDPAddr).Port))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	sendAck(t, phone, invite, res, h.publicUDP)
	return invite, res, rtp
}

// auditTaggedAnswerHook answers every out-of-dialog INVITE with 200 + SDP, a
// fresh To tag and a Contact, and publishes the tag. In-dialog INVITEs (To
// tag present) fall through to reInvite when it is non-nil, else to a 200
// with the switch's SDP.
func auditTaggedAnswerHook(f *fakeSwitch, tags chan<- string,
	reInvite func(req *sip.Request, tx sip.ServerTransaction)) func(*sip.Request, sip.ServerTransaction) bool {
	return func(req *sip.Request, tx sip.ServerTransaction) bool {
		if _, inDialog := req.To().Params.Get("tag"); inDialog && reInvite != nil {
			reInvite(req, tx)
			return true
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(f.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(f.addr)}})
		if _, inDialog := req.To().Params.Get("tag"); !inDialog {
			tag := sip.GenerateTagN(12)
			res.To().Params.Add("tag", tag)
			if tags != nil {
				select {
				case tags <- tag:
				default:
				}
			}
		}
		_ = tx.Respond(res)
		return true
	}
}

// auditPhoneAnswers makes a test client answer INVITEs with 200 + a plain
// RTP body on rtpPort (bodyFn, when set, supplies the body instead), and
// every other request with 200.
func auditPhoneAnswers(phone *client, rtpPort int, bodyFn func(req *sip.Request) string) {
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		body := phoneOfferSDP(rtpPort)
		if bodyFn != nil {
			body = bodyFn(req)
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		if _, ok := res.To().Params.Get("tag"); !ok {
			res.To().Params.Add("tag", sip.GenerateTagN(12))
		}
		_ = tx.Respond(res)
	})
}

// auditRegisterPhone registers user through the proxy (the fake switch does
// not challenge) and returns the Request-URI FreeSWITCH would call it on.
func auditRegisterPhone(t *testing.T, h *harness, phone *client, user string) sip.Uri {
	t.Helper()
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	before := len(h.fs.contacts())
	if res := phone.do(t, phone.buildRegister(user, "example.com", 600, ""), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	stored := h.fs.contacts()
	if len(stored) <= before {
		t.Fatal("nothing registered")
	}
	var ruri sip.Uri
	if err := sip.ParseUri(stored[len(stored)-1], &ruri); err != nil {
		t.Fatalf("stored contact %q: %v", stored[len(stored)-1], err)
	}
	return ruri
}

// auditSwapFakeSwitch replaces the harness's fake FreeSWITCH with one whose
// BYE handler the test supplies. It is startFakeSwitch with that single
// difference; the handler must be registered before the switch serves, which
// is why the existing switch cannot simply be re-hooked.
func auditSwapFakeSwitch(t *testing.T, h *harness, bye func(f *fakeSwitch, req *sip.Request, tx sip.ServerTransaction)) {
	t.Helper()
	h.fs.stop()
	addr := h.upstream
	f := &fakeSwitch{t: t, addr: addr, challenge: true, rtpPort: freePort(t), done: make(chan struct{})}
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	f.ua = ua
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	cli, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatal(err)
	}
	f.cli = cli
	srv.OnRegister(f.onRegister)
	srv.OnInvite(f.onInvite)
	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) { f.record(req) })
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		f.record(req)
		bye(f, req, tx)
	})
	srv.OnCancel(func(req *sip.Request, tx sip.ServerTransaction) {
		f.record(req)
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	srv.OnNoRoute(func(req *sip.Request, tx sip.ServerTransaction) {
		f.record(req)
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var conn *net.UDPConn
	for i := 0; i < 50; i++ {
		if conn, err = net.ListenUDP("udp", uaddr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("rebind fake switch %s: %v", addr, err)
	}
	f.conn = conn
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go func() { <-ctx.Done(); conn.Close() }()
	go func() {
		defer close(f.done)
		_ = srv.TransportLayer().ServeUDP(conn)
	}()
	h.fs = f
}

// auditInDialogWithBody is fakeSwitch.inDialog with a body: an in-dialog
// request from the switch (as the UAS of a call it received), carrying SDP.
func auditInDialogWithBody(t *testing.T, f *fakeSwitch, method sip.RequestMethod, invite *sip.Request,
	toTag string, cseq uint32, body string) *sip.Response {
	t.Helper()
	target, ok := fsip.ContactURI(invite)
	if !ok {
		t.Fatal("the INVITE the switch received carried no Contact")
	}
	req := sip.NewRequest(method, target)
	from := &sip.FromHeader{Address: invite.To().Address, Params: sip.NewParams()}
	from.Params.Add("tag", toTag)
	req.AppendHeader(from)
	to := &sip.ToHeader{Address: invite.From().Address, Params: sip.NewParams()}
	if tag, ok := invite.From().Params.Get("tag"); ok {
		to.Params.Add("tag", tag)
	}
	req.AppendHeader(to)
	sip.CopyHeaders("Call-ID", invite, req)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: cseq, MethodName: method})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(f.addr)}})
	for _, hdr := range invite.GetHeaders("Record-Route") {
		if rr, ok := hdr.(*sip.RecordRouteHeader); ok {
			req.AppendHeader(&sip.RouteHeader{Address: rr.Address})
		}
	}
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "127.0.0.1", Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	if body != "" {
		req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		req.SetBody([]byte(body))
	}
	req.SetTransport("UDP")
	req.SetDestination(f.topRouteDest(t, req))
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("fake switch %s: %v", method, err)
	}
	defer tx.Terminate()
	for {
		select {
		case res := <-tx.Responses():
			if res != nil && res.StatusCode >= 200 {
				if method == sip.INVITE && res.StatusCode/100 == 2 {
					auditAckInDialog(t, f, req, res)
				}
				return res
			}
		case <-tx.Done():
			t.Fatalf("fake switch %s: %v", method, tx.Err())
		case <-ctx.Done():
			t.Fatalf("fake switch %s timed out", method)
		}
	}
}

// auditAckInDialog ACKs a 2xx to a re-INVITE the switch sent.
func auditAckInDialog(t *testing.T, f *fakeSwitch, inv *sip.Request, res *sip.Response) {
	t.Helper()
	ack := sip.NewRequest(sip.ACK, inv.Recipient)
	sip.CopyHeaders("From", inv, ack)
	sip.CopyHeaders("Call-ID", inv, ack)
	ack.AppendHeader(sip.HeaderClone(res.To()))
	ack.AppendHeader(&sip.CSeqHeader{SeqNo: inv.CSeq().SeqNo, MethodName: sip.ACK})
	mf := sip.MaxForwardsHeader(70)
	ack.AppendHeader(&mf)
	for _, hdr := range inv.GetHeaders("Route") {
		ack.AppendHeader(sip.HeaderClone(hdr))
	}
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "127.0.0.1", Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	ack.PrependHeader(via)
	ack.SetTransport("UDP")
	ack.SetDestination(f.topRouteDest(t, ack))
	ack.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}
	if err := f.cli.WriteRequest(ack); err != nil {
		t.Logf("fake switch re-INVITE ACK: %v", err)
	}
}

// auditPhoneReInvite sends a re-INVITE from the phone inside the dialog the
// initial INVITE/200 established and returns the final response.
func auditPhoneReInvite(t *testing.T, h *harness, phone *client, invite *sip.Request, res *sip.Response,
	cseq uint32, body string) (*sip.Request, *sip.Response) {
	t.Helper()
	re := sip.NewRequest(sip.INVITE, invite.Recipient)
	sip.CopyHeaders("From", invite, re)
	sip.CopyHeaders("Call-ID", invite, re)
	re.AppendHeader(sip.HeaderClone(res.To()))
	re.AppendHeader(&sip.CSeqHeader{SeqNo: cseq, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	re.AppendHeader(&mf)
	re.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
	re.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: strings.ToUpper(phone.transport),
		Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	if phone.transport == "udp" {
		via.Params.Add("rport", "")
	}
	re.PrependHeader(via)
	copyRouteFromRecordRoute(res, re)
	re.SetBody([]byte(body))
	dest := h.publicUDP
	if phone.transport == "ws" {
		dest = h.publicWS
	}
	reRes := phone.do(t, re, dest)
	return re, reRes
}

// auditRecvUntil reads datagrams on conn until want matches one or d
// expires; it reports whether a match was seen.
func auditRecvUntil(conn *net.UDPConn, d time.Duration, want func([]byte) bool) bool {
	deadline := time.Now().Add(d)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if want(buf[:n]) {
			return true
		}
	}
	return false
}

func auditUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func auditUDPPort(c *net.UDPConn) int { return c.LocalAddr().(*net.UDPAddr).Port }

func auditLocalAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}
