package edge

// Phase 3 resource-balance tests for the edge plane (docs/audit). Each test
// drives calls through one exit path and asserts that every port went back
// to its pool, the dialog table (any state) and the registration table are
// empty, and the goroutines owned by edge/media/pion are back to baseline
// (runtime.Stack with a bounded retry; no goleak).

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// audit: P2-EDG-027
// Shutdown with live dialogs: three confirmed calls and one INVITE still
// ringing upstream when Run's context is cancelled. After Run returns no
// port, dialog record or owned goroutine may remain.
func TestAuditBalanceShutdownWithLiveDialogs(t *testing.T) {
	settle()
	baseOwned, _ := auditOwnedGoroutines()
	baseTotal := runtime.NumGoroutine()

	h := startHarness(t, false)
	tags := make(chan string, 8)
	answer := auditTaggedAnswerHook(h.fs, tags, nil)
	silent := h.fs.silentHook()
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		if req.Recipient.User == "ring" {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
			return silent(req, tx)
		}
		return answer(req, tx)
	})

	var phones []*client
	for i := 0; i < 3; i++ {
		p := newUDPClient(t)
		phones = append(phones, p)
		auditPhoneCall(t, h, p)
	}
	if n := h.srv.ActiveCalls(); n != 3 {
		t.Fatalf("ActiveCalls = %d, want 3 before shutdown", n)
	}
	ringer := newUDPClient(t)
	phones = append(phones, ringer)
	ringInv := ringer.buildInvite("1009", "ring", "example.com", phoneOfferSDP(30901))
	ringInv.SetTransport("UDP")
	ringInv.SetDestination(h.publicUDP)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tx, err := ringer.cli.TransactionRequest(ctx, ringInv)
		if err != nil {
			return
		}
		defer tx.Terminate()
		select {
		case <-tx.Done():
		case <-ctx.Done():
		}
	}()
	if got := h.fs.waitFor(sip.INVITE, 4, 3*time.Second); len(got) < 4 {
		t.Fatalf("the ringing INVITE never reached FreeSWITCH (%d INVITEs)", len(got))
	}
	time.Sleep(100 * time.Millisecond)

	// Shut the plane down with everything live.
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	auditWaitBalanced(t, h, "after shutdown", 3*time.Second)
	auditWaitOwnedGoroutines(t, "after shutdown", baseOwned, 5*time.Second)

	// Everything else the test started is stopped too; the process-wide
	// count must come back (sipgo's Timer J/K goroutines need up to ~32 s).
	h.fs.stop()
	h.fs = nil
	for _, p := range phones {
		p.cancel()
	}
	deadline := time.Now().Add(40 * time.Second)
	for runtime.NumGoroutine() > baseTotal+2 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(200 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseTotal+2 {
		_, dump := auditOwnedGoroutines()
		t.Errorf("process goroutines %d > baseline %d (+2) 40 s after shutdown; owned stacks:\n%s", n, baseTotal, dump)
	}
}

// audit: P3-RB-bye (resource-balance baseline; no Phase 2 finding)
// Normal BYE in both directions, plus register/un-register, N times.
func TestAuditBalanceNormalBye(t *testing.T) {
	h := startHarness(t, false)
	tags := make(chan string, 16)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	settle()
	baseOwned, _ := auditOwnedGoroutines()

	const n = 5
	for i := 0; i < n; i++ {
		phone := newUDPClient(t)
		invite, res, _ := auditPhoneCall(t, h, phone)
		waitForDialog(t, h, fsip.CallID(invite))
		if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
			t.Errorf("round %d phone BYE: %d", i, r.StatusCode)
		}
		phone.cancel()
	}
	for i := 0; i < n; i++ {
		phone := newUDPClient(t)
		ruri := auditRegisterPhone(t, h, phone, "1001")
		rtp := auditUDP(t)
		auditPhoneAnswers(phone, auditUDPPort(rtp), nil)
		res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
		if res.StatusCode != 200 {
			t.Fatalf("round %d inbound INVITE: %d", i, res.StatusCode)
		}
		waitForDialog(t, h, fsip.CallID(res))
		h.fs.sendAckTo2xx(t, res)
		if b := h.fs.uacBye(t, res); b.StatusCode != 200 {
			t.Errorf("round %d FreeSWITCH BYE: %d", i, b.StatusCode)
		}
		if r := phone.do(t, phone.buildRegister("1001", "example.com", 0, ""), h.publicUDP); r.StatusCode != 200 {
			t.Errorf("round %d un-REGISTER: %d", i, r.StatusCode)
		}
		phone.cancel()
	}
	auditWaitBalanced(t, h, "normal BYE", 5*time.Second)
	if c := h.srv.loc.Count(); c != 0 {
		t.Errorf("registration bindings left: %d", c)
	}
	auditWaitOwnedGoroutines(t, "normal BYE", baseOwned, 5*time.Second)
}

// audit: P2-EDG-007
// CANCEL racing the 200 (RFC 3261 §9.1, §16.7 step 10): the phone cancels,
// the CANCEL reaches FreeSWITCH, and FreeSWITCH's 200 crosses it. The SBC
// must ACK and BYE that 200 and release the call's resources; the caller is
// gone and will never ACK.
func TestAuditBalanceCancelRaces200(t *testing.T) {
	h := startHarness(t, false)
	pending := make(chan *sip.Response, 1)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		ok := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		ok.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		ok.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		ok.To().Params.Add("tag", sip.GenerateTagN(12))
		select {
		case pending <- ok:
		default:
		}
		return true // no final on the transaction: the test sends the 200 later
	})
	settle()
	baseOwned, _ := auditOwnedGoroutines()

	const n = 3
	for i := 0; i < n; i++ {
		phone := newUDPClient(t)
		invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30950+i))
		invite.SetTransport("UDP")
		invite.SetDestination(h.publicUDP)
		cancelReq := buildCancelFor(invite)
		done := make(chan struct{})
		go func() {
			defer close(done)
			ctx, cancel := timeoutCtx(10 * time.Second)
			defer cancel()
			tx, err := phone.cli.TransactionRequest(ctx, invite)
			if err != nil {
				return
			}
			defer tx.Terminate()
			for {
				select {
				case res := <-tx.Responses():
					if res != nil && res.StatusCode >= 200 {
						return
					}
				case <-tx.Done():
					return
				case <-ctx.Done():
					return
				}
			}
		}()
		var ok *sip.Response
		select {
		case ok = <-pending:
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: FreeSWITCH never got the INVITE", i)
		}
		cancelsBefore := len(h.fs.received(sip.CANCEL))
		if r := phone.do(t, cancelReq, h.publicUDP); r.StatusCode != 200 {
			t.Fatalf("round %d CANCEL: %d", i, r.StatusCode)
		}
		h.fs.waitFor(sip.CANCEL, cancelsBefore+1, 3*time.Second)
		acksBefore := len(h.fs.received(sip.ACK))
		byesBefore := len(h.fs.received(sip.BYE))
		h.fs.sendResponse(t, ok) // the 200 that crossed the CANCEL
		<-done

		acks := len(h.fs.waitFor(sip.ACK, acksBefore+1, 3*time.Second)) - acksBefore
		byes := len(h.fs.waitFor(sip.BYE, byesBefore+1, 3*time.Second)) - byesBefore
		if acks < 1 || byes < 1 {
			t.Errorf("P2-EDG-007 round %d: FreeSWITCH's 200 that raced the CANCEL got %d ACK(s) and %d BYE(s) from the SBC, want ≥1 each; ActiveCalls=%d",
				i, acks, byes, h.srv.ActiveCalls())
		}
		phone.cancel()
	}
	auditWaitBalanced(t, h, "CANCEL/200 race", 3*time.Second)
	auditWaitOwnedGoroutines(t, "CANCEL/200 race", baseOwned, 5*time.Second)
}

// audit: P2-EDG-032
// Media timeout: calls with no RTP at all under a 1 s rtp_timeout (hot
// reloaded before the calls). The watchdog must release everything.
func TestAuditBalanceMediaTimeout(t *testing.T) {
	h := startHarness(t, false)
	auditReplaceConfig(h, func(c *config.Config) { c.Listen.Media.RTPTimeout = config.Duration(time.Second) })
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	settle()
	baseOwned, _ := auditOwnedGoroutines()
	for i := 0; i < 3; i++ {
		phone := newUDPClient(t)
		invite, _, _ := auditPhoneCall(t, h, phone)
		waitForDialog(t, h, fsip.CallID(invite))
	}
	auditWaitBalanced(t, h, "media timeout", 8*time.Second)
	auditWaitOwnedGoroutines(t, "media timeout", baseOwned, 5*time.Second)
}

// audit: P2-MED-011
// Hot reload mid-call that moves the public RTP range away from the ports
// live calls hold. After the calls end, every port must be back and the
// pool's own accounting must be consistent (inUse <= total).
func TestAuditBalanceReloadMidCall(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	settle()
	baseOwned, _ := auditOwnedGoroutines()

	type live struct {
		phone  *client
		invite *sip.Request
		res    *sip.Response
	}
	var calls []live
	for i := 0; i < 3; i++ {
		phone := newUDPClient(t)
		invite, res, _ := auditPhoneCall(t, h, phone)
		waitForDialog(t, h, fsip.CallID(invite))
		calls = append(calls, live{phone, invite, res})
	}
	oldMin := h.store.Current().RTP.Public.PortMin
	auditReplaceConfig(h, func(c *config.Config) {
		c.RTP.Public.PortMin = oldMin + 100
		c.RTP.Public.PortMax = oldMin + 199
	})
	inUse, total := h.srv.pubPool.Stats()
	t.Logf("after reload with 3 live calls: public pool inUse=%d total=%d", inUse, total)
	if inUse > total {
		t.Errorf("P2-MED-011 confirmed: public pool reports inUse=%d > total=%d after a range-shrinking reload", inUse, total)
	}
	// A call placed after the reload lands in the new range.
	phone := newUDPClient(t)
	invite, res, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	calls = append(calls, live{phone, invite, res})

	for i, c := range calls {
		if r := c.phone.do(t, buildBye(c.phone, c.invite, c.res), h.publicUDP); r.StatusCode != 200 {
			t.Errorf("call %d BYE: %d", i, r.StatusCode)
		}
	}
	auditWaitBalanced(t, h, "reload mid-call", 5*time.Second)
	auditWaitOwnedGoroutines(t, "reload mid-call", baseOwned, 5*time.Second)

	// The released out-of-range ports must be bindable again (not leaked).
	for p := oldMin; p < oldMin+8; p++ {
		c, err := net.ListenUDP("udp", auditLocalAddr(p))
		if err != nil {
			t.Errorf("port %d from the pre-reload range is still bound after its call ended: %v", p, err)
			continue
		}
		_ = c.Close()
	}
}
