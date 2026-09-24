package edge

// Regression tests for the edge dialog/transaction model (issue #9) whose
// findings the Phase 3 audit could not turn into a failing test.

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// auditObservingTx is a sip.ServerTransaction that hands every response to
// a callback instead of the network, so a test can observe the proxy's
// state at the exact moment it relays a response. Only the methods the
// INVITE paths call are implemented; any other call panics on the nil
// embedded interface.
type auditObservingTx struct {
	sip.ServerTransaction
	onRespond func(res *sip.Response)
	done      chan struct{}
}

func newAuditObservingTx(onRespond func(res *sip.Response)) *auditObservingTx {
	return &auditObservingTx{onRespond: onRespond, done: make(chan struct{})}
}

func (f *auditObservingTx) Respond(res *sip.Response) error { f.onRespond(res); return nil }
func (f *auditObservingTx) OnCancel(sip.FnTxCancel) bool    { return true }
func (f *auditObservingTx) OnTerminate(sip.FnTxTerminate) bool {
	return true
}
func (f *auditObservingTx) Done() <-chan struct{}     { return f.done }
func (f *auditObservingTx) Err() error                { return nil }
func (f *auditObservingTx) Terminate()                {}
func (f *auditObservingTx) Acks() <-chan *sip.Request { return nil }

// audit: P2-EDG-018
// RFC 3261 §13.2.2.4: the ACK for a 2xx must reach the UAS, and the caller
// sends it the moment it sees the 2xx. So the dialog must be on record
// BEFORE the 2xx leaves the proxy — otherwise an ACK that is quick enough
// finds no route and is dropped. TestAuditAckRacesCommit could not hit the
// window over loopback; this test removes the network from the question by
// checking the dialog table from inside the relay itself, for both INVITE
// directions.
func TestAuditDialogConfirmedBeforeRelay(t *testing.T) {
	t.Run("fs-to-client", func(t *testing.T) {
		h := startHarness(t, false)
		phone := newUDPClient(t)
		ruri := auditRegisterPhone(t, h, phone, "1001")
		phoneRTP := auditUDP(t)
		auditPhoneAnswers(phone, auditUDPPort(phoneRTP), nil)

		req := sip.NewRequest(sip.INVITE, ruri)
		from := &sip.FromHeader{Address: sip.Uri{User: "3003", Host: "example.com"}, Params: sip.NewParams()}
		from.Params.Add("tag", sip.GenerateTagN(12))
		req.AppendHeader(from)
		req.AppendHeader(&sip.ToHeader{Address: ruri, Params: sip.NewParams()})
		callID := sip.CallIDHeader(fmt.Sprintf("audit-ackrace-%d", time.Now().UnixNano()))
		req.AppendHeader(&callID)
		req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
		mf := sip.MaxForwardsHeader(70)
		req.AppendHeader(&mf)
		req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: "127.0.0.1", Port: portOf(h.upstream)}})
		via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
			Host: "127.0.0.1", Port: portOf(h.upstream), Params: sip.NewParams()}
		via.Params.Add("branch", sip.GenerateBranchN(16))
		req.PrependHeader(via)
		req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		req.SetBody([]byte(phoneOfferSDP(h.fs.rtpPort)))
		req.SetTransport("UDP")
		req.SetSource(h.upstream)

		auditExpectConfirmedAtRelay(t, h, func(tx sip.ServerTransaction) { h.srv.inviteToClient(req, tx) })
	})
	t.Run("client-to-fs", func(t *testing.T) {
		h := startHarness(t, false)
		phone := newUDPClient(t)
		req := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30777))
		req.SetTransport("UDP")
		req.SetSource(phone.local)
		src, _ := fsip.SourceAddrPort(req)

		auditExpectConfirmedAtRelay(t, h, func(tx sip.ServerTransaction) { h.srv.inviteToUpstream(req, tx, src) })
	})
}

// auditExpectConfirmedAtRelay runs one INVITE path against an observing
// server transaction and fails unless the call is already counted as up at
// the moment its 2xx is handed to the transaction.
func auditExpectConfirmedAtRelay(t *testing.T, h *harness, run func(tx sip.ServerTransaction)) {
	t.Helper()
	var mu sync.Mutex
	seen2xx, upAtRelay := false, -1
	tx := newAuditObservingTx(func(res *sip.Response) {
		if res.StatusCode/100 != 2 {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !seen2xx {
			seen2xx, upAtRelay = true, h.srv.ActiveCalls()
		}
	})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		run(tx)
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the INVITE path never returned")
	}
	mu.Lock()
	defer mu.Unlock()
	if !seen2xx {
		t.Fatal("no 2xx was relayed")
	}
	if upAtRelay < 1 {
		t.Errorf("P2-EDG-018 confirmed: the 2xx was relayed while the dialog was not yet on record (active calls %d); an ACK sent on receipt finds no route", upAtRelay)
	}
}

// auditOrigin extracts the o= session id and version of an SDP body.
func auditOrigin(t *testing.T, body []byte) (id, version uint64) {
	t.Helper()
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "o=") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			break
		}
		id, err1 := strconv.ParseUint(f[1], 10, 64)
		version, err2 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			break
		}
		return id, version
	}
	t.Fatalf("no parseable o= line in:\n%s", body)
	return 0, 0
}

// audit: P2-SDP-002
// RFC 3264 §8: each new body a leg is sent keeps the o= session id and
// increments the version by exactly one. A phone re-INVITEs once; the two
// offers FreeSWITCH received, and the two answers the phone received, must
// each carry consecutive versions of one session id.
func TestAuditReInviteOriginVersionIncrementsByOne(t *testing.T) {
	h := startHarness(t, false)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	<-tags
	waitForDialog(t, h, fsip.CallID(invite))

	_, reRes := auditPhoneReInvite(t, h, phone, invite, res, 2, phoneOfferSDP(auditUDPPort(phoneRTP)))
	if reRes.StatusCode != 200 {
		t.Fatalf("re-INVITE: %d", reRes.StatusCode)
	}
	offers := h.fs.waitFor(sip.INVITE, 2, 3*time.Second)
	if len(offers) != 2 {
		t.Fatalf("FreeSWITCH saw %d INVITEs, want 2", len(offers))
	}
	for _, leg := range []struct {
		name          string
		first, second []byte
	}{
		{"FreeSWITCH leg (offers)", offers[0].Body(), offers[1].Body()},
		{"phone leg (answers)", res.Body(), reRes.Body()},
	} {
		id1, v1 := auditOrigin(t, leg.first)
		id2, v2 := auditOrigin(t, leg.second)
		if id1 != id2 || v2 != v1+1 {
			t.Errorf("P2-SDP-002 confirmed: %s o= went %d/%d → %d/%d; want the same id and version +1",
				leg.name, id1, v1, id2, v2)
		}
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// audit: P2-EDG-004
// The forked half of P2-EDG-004: once a dialog is confirmed by one fork's
// 2xx, a 2xx from ANOTHER fork is a second dialog the proxy has no media
// anchor for. RFC 3261 §13.2.2.4 says it must be ACKed (else the UAS
// retransmits it and then tears the call down) and, when unwanted, BYEd.
// The confirmed call must be untouched.
func TestAuditSecondFork2xxAckedAndByed(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		res.To().Params.Add("tag", "fork-a")
		_ = tx.Respond(res)
		other := res.Clone()
		other.To().Params.Add("tag", "fork-b")
		go func() {
			time.Sleep(200 * time.Millisecond)
			_ = h.fs.srv.TransportLayer().WriteMsg(other)
		}()
		return true
	})
	phone := newUDPClient(t)
	invite, res, _ := auditPhoneCall(t, h, phone)
	if tag := fsip.ToTag(res); tag != "fork-a" {
		t.Fatalf("phone's 200 carries To tag %q, want fork-a", tag)
	}
	waitForDialog(t, h, fsip.CallID(invite))

	tagged := func(method sip.RequestMethod, tag string) bool {
		for _, r := range h.fs.received(method) {
			if fsip.ToTag(r) == tag {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !(tagged(sip.ACK, "fork-b") && tagged(sip.BYE, "fork-b")) {
		time.Sleep(20 * time.Millisecond)
	}
	if !tagged(sip.ACK, "fork-b") || !tagged(sip.BYE, "fork-b") {
		t.Errorf("P2-EDG-004 confirmed: fork B's 2xx was not ACKed and BYEd (ACK %v, BYE %v)",
			tagged(sip.ACK, "fork-b"), tagged(sip.BYE, "fork-b"))
	}
	if tagged(sip.BYE, "fork-a") || h.srv.ActiveCalls() != 1 {
		t.Errorf("the confirmed dialog (fork A) was disturbed: active calls %d", h.srv.ActiveCalls())
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}
