package edge

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Global call admission control (issue #114): shield.max_sessions caps the
// calls holding a session slot and shield.invite_rate_limit bounds new
// out-of-dialog INVITEs. An admitted peer over either limit gets 503 +
// Retry-After and costs no media port; an unknown public source keeps the
// silent drop; a re-INVITE is never charged; every teardown path gives the
// slot back.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// setShield publishes the hot admission settings of the harness, the way a
// reload does.
func setShield(h *harness, maxSessions int, inviteRate string) {
	auditReplaceConfig(h, func(c *config.Config) {
		c.Shield.MaxSessions = maxSessions
		c.Shield.InviteRateLimit = inviteRate
	})
}

// portsInUse is the media port pairs held on both planes.
func portsInUse(h *harness) int {
	pub, _ := h.srv.pubPool.Stats()
	priv, _ := h.srv.privPool.Stats()
	return pub + priv
}

// assertBusy checks a 503 carrying Retry-After.
func assertBusy(t *testing.T, res *sip.Response, retryAfter string) {
	t.Helper()
	if res.StatusCode != 503 {
		t.Fatalf("got %d %s, want 503", res.StatusCode, res.Reason)
	}
	if got := headerValue(res, "Retry-After"); got != retryAfter {
		t.Errorf("Retry-After = %q, want %q", got, retryAfter)
	}
}

// waitSessions waits for the dialog table to hold exactly n session slots.
func waitSessions(t *testing.T, h *harness, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.dialogs.sessionCount() == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session count = %d, want %d", h.srv.dialogs.sessionCount(), n)
}

// phoneCallStatus places one client -> switch INVITE and returns the final
// status.
func phoneCallStatus(t *testing.T, h *harness, phone *client) int {
	t.Helper()
	return phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30500)), h.publicUDP).StatusCode
}

func phoneInvite(t *testing.T, h *harness, phone *client) *sip.Response {
	t.Helper()
	return phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30500)), h.publicUDP)
}

// A registered client over the cap gets 503 + Retry-After; nothing reaches
// the switch and no media port is taken; the next call after a hang-up
// goes through.
func TestSessionCapClientToSwitch(t *testing.T) {
	h := startHarness(t, false)
	setShield(h, 1, "")
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	invite, res, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	inUse := portsInUse(h)

	assertBusy(t, phoneInvite(t, h, phone), "5")
	if got := h.fs.received(sip.INVITE); len(got) != 1 {
		t.Errorf("the switch saw %d INVITEs, want only the first call's", len(got))
	}
	if n := portsInUse(h); n != inUse {
		t.Errorf("media ports in use = %d after the refusal, want %d", n, inUse)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectSessionCap: 1})
	if n := h.srv.dialogs.sessionCount(); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}

	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Errorf("call after the slot freed: %d, want 200", code)
	}
}

// The switch placing a call to a registered client is held to the cap too.
func TestSessionCapSwitchToClient(t *testing.T) {
	h := startHarness(t, false)
	setShield(h, 1, "")
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	rtp := auditUDP(t)
	var offered atomic.Int32
	auditPhoneAnswers(phone, auditUDPPort(rtp), func(*sip.Request) string {
		offered.Add(1)
		return phoneOfferSDP(auditUDPPort(rtp))
	})
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("first call: %d", res.StatusCode)
	}
	waitForDialog(t, h, fsip.CallID(res))
	h.fs.sendAckTo2xx(t, res)
	inUse := portsInUse(h)

	assertBusy(t, h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)), "5")
	if n := offered.Load(); n != 1 {
		t.Errorf("the client saw %d INVITEs, want only the first call's", n)
	}
	if n := portsInUse(h); n != inUse {
		t.Errorf("media ports in use = %d after the refusal, want %d", n, inUse)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectSessionCap: 1})

	if b := h.fs.uacBye(t, res); b.StatusCode != 200 {
		t.Fatalf("BYE: %d", b.StatusCode)
	}
	waitForRelease(t, h)
	if r := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)); r.StatusCode != 200 {
		t.Errorf("call after the slot freed: %d, want 200", r.StatusCode)
	}
}

// The switch placing a call out through a carrier is held to the cap.
func TestSessionCapSwitchToCarrier(t *testing.T) {
	o := startOutboundRig(t)
	setShield(o.harness, 1, "")
	answerWithTag(o.carrier)
	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("first call: %d", res.StatusCode)
	}
	o.fs.sendAckTo2xx(t, res)
	waitForDialog(t, o.harness, fsip.CallID(res))
	inUse := portsInUse(o.harness)

	assertBusy(t, o.fs.call(t, o.ruri("+442071234568"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort)), "5")
	if got := o.carrier.received(sip.INVITE); len(got) != 1 {
		t.Errorf("the carrier saw %d INVITEs, want only the first call's", len(got))
	}
	if n := portsInUse(o.harness); n != inUse {
		t.Errorf("media ports in use = %d after the refusal, want %d", n, inUse)
	}
	assertRejects(t, o.harness, map[inviteReject]uint64{rejectSessionCap: 1})
}

// A carrier delivering a call is held to the cap.
func TestSessionCapCarrierToSwitch(t *testing.T) {
	carrier := newUDPClient(t)
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(carrier.local)), "", nil)
	setShield(rig.harness, 1, "")
	rig.cs.setInviteHook(auditTaggedAnswerHook(rig.cs, nil, nil))
	first := carrier.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(30500))
	res := carrier.do(t, first, rig.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("first call: %d", res.StatusCode)
	}
	waitForDialog(t, rig.harness, fsip.CallID(first))
	inUse := portsInUse(rig.harness)

	assertBusy(t, carrier.do(t, carrier.buildInvite("+442071234568", "+15551230001", "example.com", phoneOfferSDP(30502)), rig.publicUDP), "5")
	if got := rig.cs.received(sip.INVITE); len(got) != 1 {
		t.Errorf("the switch saw %d INVITEs, want only the first call's", len(got))
	}
	if n := portsInUse(rig.harness); n != inUse {
		t.Errorf("media ports in use = %d after the refusal, want %d", n, inUse)
	}
	assertRejects(t, rig.harness, map[inviteReject]uint64{rejectSessionCap: 1})

	if r := carrier.do(t, buildBye(carrier, first, res), rig.publicUDP); r.StatusCode != 200 {
		t.Fatalf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, rig.harness)
	if r := carrier.do(t, carrier.buildInvite("+442071234569", "+15551230002", "example.com", phoneOfferSDP(30504)), rig.publicUDP); r.StatusCode != 200 {
		t.Errorf("call after the slot freed: %d, want 200", r.StatusCode)
	}
}

// An unknown public source keeps the silent drop when the cap is reached,
// while an admitted peer is told 503.
func TestSessionCapUnknownSourceStaysSilent(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setShield(h, 1, "")
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Fatalf("first call: %d", code)
	}

	other := newUDPClient(t)
	expectSilence(t, other, other.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30502)), h.publicUDP)
	assertRejects(t, h, nil)
	if n := admissionDrops(h, dropInviteNotAdmitted); n == 0 {
		t.Error("the unknown source's INVITE was not counted as an admission drop")
	}

	assertBusy(t, phoneInvite(t, h, phone), "5")
	assertRejects(t, h, map[inviteReject]uint64{rejectSessionCap: 1})
}

// A re-INVITE inside a call is not a new call: it takes no slot and is not
// refused at the cap.
func TestSessionCapReInviteNotCharged(t *testing.T) {
	h := startHarness(t, false)
	setShield(h, 1, "")
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	invite, res, rtp := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("switch saw %d ACKs", len(acks))
	}
	for cseq := uint32(2); cseq <= 3; cseq++ {
		_, re := auditPhoneReInvite(t, h, phone, invite, res, cseq, phoneOfferSDP(auditUDPPort(rtp)))
		if re.StatusCode != 200 {
			t.Fatalf("re-INVITE %d at the cap: %d, want 200", cseq, re.StatusCode)
		}
	}
	if n := h.srv.dialogs.sessionCount(); n != 1 {
		t.Errorf("sessions = %d after re-INVITEs, want 1", n)
	}
	assertRejects(t, h, nil)
}

// max_sessions is hot: a reload applies to the next INVITE, 0 means what
// the rtp range can anchor, and running calls are never torn down.
func TestSessionCapHotReload(t *testing.T) {
	h := startHarness(t, false)
	setShield(h, 1, "")
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Fatalf("call 1: %d", code)
	}
	assertBusy(t, phoneInvite(t, h, phone), "5")

	setShield(h, 2, "")
	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Fatalf("call 2 after raising the cap: %d", code)
	}
	assertBusy(t, phoneInvite(t, h, phone), "5")

	// Lowering below the running count refuses new calls and keeps the old.
	setShield(h, 1, "")
	assertBusy(t, phoneInvite(t, h, phone), "5")
	if n := h.srv.ActiveCalls(); n != 2 {
		t.Errorf("active calls = %d after lowering the cap, want 2 (never torn down)", n)
	}

	setShield(h, 0, "")
	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Errorf("call 3 with max_sessions 0 (the rtp capacity): %d", code)
	}
}

// The session gauge follows the table, ringing calls included.
func TestSessionGauge(t *testing.T) {
	h := startHarness(t, false)
	gauge := func() int64 { return h.srv.metrics.Snapshot().ActiveSessions }
	if gauge() != 0 {
		t.Fatalf("gauge = %d at start", gauge())
	}
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		return true
	})
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30500))
	cancel := buildCancelFor(invite)
	uac := phoneUAC(t, h, phone, invite)
	uac.provisional(t, 180)
	if g := gauge(); g != 1 {
		t.Errorf("gauge = %d for a ringing call, want 1", g)
	}
	if h.srv.ActiveCalls() != 0 {
		t.Errorf("a ringing call counted as active")
	}
	if r := phone.do(t, cancel, h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("CANCEL: %d", r.StatusCode)
	}
	waitSessions(t, h, 0)
	if g := gauge(); g != 0 {
		t.Errorf("gauge = %d after CANCEL, want 0", g)
	}
}

// ---------------------------------------------------------------------
// Leak test: every teardown path gives the slot back
// ---------------------------------------------------------------------

// cancelRinging sends invite from c to dest, waits until the far end has
// it, CANCELs and waits for the 487.
func cancelRinging(t *testing.T, h *harness, c *client, invite *sip.Request, farSeen func() bool) {
	t.Helper()
	cancel := buildCancelFor(invite)
	uac := phoneUAC(t, h, c, invite)
	deadline := time.Now().Add(3 * time.Second)
	for !farSeen() {
		if time.Now().After(deadline) {
			t.Fatal("the far end never saw the INVITE")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r := c.do(t, cancel, h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("CANCEL: %d", r.StatusCode)
	}
	for {
		if r := uac.next(t, 5*time.Second); r.StatusCode >= 200 {
			if r.StatusCode != 487 {
				t.Fatalf("INVITE final after CANCEL = %d, want 487", r.StatusCode)
			}
			return
		}
	}
}

func TestSessionSlotReleasedOnEveryTeardown(t *testing.T) {
	// Each case runs one call to its end with max_sessions 1, waits for the
	// slot to come back and then runs next(): a fresh call that the cap
	// would refuse had the slot leaked. next is nil when the process is
	// shutting down.
	type scenario func(t *testing.T) (h *harness, next func() int)

	phoneNext := func(t *testing.T, h *harness, phone *client) func() int {
		return func() int { return phoneCallStatus(t, h, phone) }
	}
	tagged := func(h *harness) { h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil)) }

	cases := []struct {
		name string
		run  scenario
	}{
		{"BYE from the caller", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			tagged(h)
			phone := newUDPClient(t)
			invite, res, _ := auditPhoneCall(t, h, phone)
			waitForDialog(t, h, fsip.CallID(invite))
			if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
				t.Fatalf("BYE: %d", r.StatusCode)
			}
			return h, phoneNext(t, h, phone)
		}},
		{"BYE from the callee", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			tags := make(chan string, 1)
			h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
			phone := newUDPClient(t)
			invite, _, _ := auditPhoneCall(t, h, phone)
			tag := <-tags
			waitForDialog(t, h, fsip.CallID(invite))
			up := waitReceived(t, h.fs, sip.INVITE, 1)[0]
			if r := h.fs.inDialog(t, sip.BYE, up, tag); r.StatusCode != 200 {
				t.Fatalf("BYE from the switch: %d", r.StatusCode)
			}
			return h, phoneNext(t, h, phone)
		}},
		{"BYE from the switch on a call it placed", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			phone := newUDPClient(t)
			ruri := auditRegisterPhone(t, h, phone, "1001")
			rtp := auditUDP(t)
			auditPhoneAnswers(phone, auditUDPPort(rtp), nil)
			res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
			if res.StatusCode != 200 {
				t.Fatalf("INVITE: %d", res.StatusCode)
			}
			waitForDialog(t, h, fsip.CallID(res))
			h.fs.sendAckTo2xx(t, res)
			if b := h.fs.uacBye(t, res); b.StatusCode != 200 {
				t.Fatalf("BYE: %d", b.StatusCode)
			}
			return h, func() int { return h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)).StatusCode }
		}},
		{"BYE from a carrier on a call the switch placed", func(t *testing.T) (*harness, func() int) {
			o := startOutboundRig(t)
			setShield(o.harness, 1, "")
			tags := answerWithTag(o.carrier)
			res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
			if res.StatusCode != 200 {
				t.Fatalf("INVITE: %d", res.StatusCode)
			}
			o.fs.sendAckTo2xx(t, res)
			tag := <-tags
			invs := o.carrier.waitFor(sip.INVITE, 1, 3*time.Second)
			waitForDialog(t, o.harness, invs[0].CallID().Value())
			if bye := o.carrier.inDialog(t, sip.BYE, invs[0], tag); bye.StatusCode != 200 {
				t.Fatalf("BYE from the carrier: %d", bye.StatusCode)
			}
			return o.harness, func() int {
				return o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort)).StatusCode
			}
		}},
		{"BYE from a carrier that delivered the call", func(t *testing.T) (*harness, func() int) {
			carrier := newUDPClient(t)
			rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(carrier.local)), "", nil)
			setShield(rig.harness, 1, "")
			rig.cs.setInviteHook(auditTaggedAnswerHook(rig.cs, nil, nil))
			invite := carrier.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(30500))
			res := carrier.do(t, invite, rig.publicUDP)
			if res.StatusCode != 200 {
				t.Fatalf("INVITE: %d", res.StatusCode)
			}
			waitForDialog(t, rig.harness, fsip.CallID(invite))
			if r := carrier.do(t, buildBye(carrier, invite, res), rig.publicUDP); r.StatusCode != 200 {
				t.Fatalf("BYE: %d", r.StatusCode)
			}
			return rig.harness, func() int {
				return carrier.do(t, carrier.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(30502)), rig.publicUDP).StatusCode
			}
		}},
		{"CANCEL from a client", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
				_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
				return true
			})
			phone := newUDPClient(t)
			cancelRinging(t, h, phone, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30500)),
				func() bool { return len(h.fs.received(sip.INVITE)) == 1 })
			tagged(h)
			return h, phoneNext(t, h, phone)
		}},
		{"CANCEL from a carrier that delivered the call", func(t *testing.T) (*harness, func() int) {
			carrier := newUDPClient(t)
			rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(carrier.local)), "", nil)
			setShield(rig.harness, 1, "")
			rig.cs.setInviteHook(rig.cs.silentHook())
			cancelRinging(t, rig.harness, carrier, carrier.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(30500)),
				func() bool { return len(rig.cs.received(sip.INVITE)) == 1 })
			rig.cs.setInviteHook(auditTaggedAnswerHook(rig.cs, nil, nil))
			return rig.harness, func() int {
				return carrier.do(t, carrier.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(30502)), rig.publicUDP).StatusCode
			}
		}},
		{"CANCEL from the switch toward a carrier", func(t *testing.T) (*harness, func() int) {
			o := startOutboundRig(t)
			setShield(o.harness, 1, "")
			o.carrier.setInviteHook(o.carrier.silentHook())
			req, final := o.fs.callAsync(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
			if got := o.carrier.waitFor(sip.INVITE, 1, 3*time.Second); len(got) != 1 {
				t.Fatalf("carrier saw %d INVITEs", len(got))
			}
			cancel := buildCancelFor(req)
			cancel.SetTransport("UDP")
			cancel.SetDestination(o.privateSIP)
			cancel.Laddr = req.Laddr
			ctx, stop := timeoutCtx(10 * time.Second)
			defer stop()
			tx, err := o.fs.cli.TransactionRequest(ctx, cancel)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Terminate()
			select {
			case <-tx.Responses():
			case <-ctx.Done():
				t.Fatal("CANCEL got no response")
			}
			if res := <-final; res == nil || res.StatusCode != 487 {
				t.Fatalf("INVITE final after CANCEL = %v, want 487", res)
			}
			answerWithTag(o.carrier)
			return o.harness, func() int {
				return o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort)).StatusCode
			}
		}},
		{"far-end 486", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
				_ = tx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
				return true
			})
			phone := newUDPClient(t)
			if code := phoneCallStatus(t, h, phone); code != 486 {
				t.Fatalf("got %d, want 486", code)
			}
			tagged(h)
			return h, phoneNext(t, h, phone)
		}},
		{"offer the edge cannot anchor (488)", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			phone := newUDPClient(t)
			bad := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 96\r\na=rtpmap:96 G729/8000\r\n"
			if r := phone.do(t, phone.buildInvite("1001", "2002", "example.com", bad), h.publicUDP); r.StatusCode != 488 {
				t.Fatalf("got %d, want 488", r.StatusCode)
			}
			tagged(h)
			return h, phoneNext(t, h, phone)
		}},
		{"RTP silence watchdog", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			h.srv.setRTPTimeout(time.Second)
			tagged(h)
			phone := newUDPClient(t)
			invite, _, _ := auditPhoneCall(t, h, phone)
			waitForDialog(t, h, fsip.CallID(invite))
			waitSessions(t, h, 0)
			return h, phoneNext(t, h, phone)
		}},
		{"answer owed to a delayed offer never arrives", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			h.fs.setInviteHook(offerIn200(h.fs, "uas-ol-leak", sdpWith(h.fs.rtpPort, "sendrecv")))
			h.srv.ackWait.Store(int64(600 * time.Millisecond))
			phone := newUDPClient(t)
			call := phoneUAC(t, h, phone, phone.buildInvite("1001", "2002", "example.com", ""))
			call.final200(t)
			waitSessions(t, h, 0)
			tagged(h)
			return h, phoneNext(t, h, phone)
		}},
		{"INVITE backstop (408)", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			h.srv.inviteBackstop.Store(int64(700 * time.Millisecond))
			h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
				_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
				return h.fs.silentHook()(req, tx)
			})
			phone := newUDPClient(t)
			if code := phoneCallStatus(t, h, phone); code != 408 {
				t.Fatalf("got %d, want 408", code)
			}
			h.srv.inviteBackstop.Store(0)
			tagged(h)
			return h, phoneNext(t, h, phone)
		}},
		{"shutdown", func(t *testing.T) (*harness, func() int) {
			h := startHarness(t, false)
			setShield(h, 1, "")
			tagged(h)
			phone := newUDPClient(t)
			invite, _, _ := auditPhoneCall(t, h, phone)
			waitForDialog(t, h, fsip.CallID(invite))
			h.srv.dialogs.close()
			h.srv.dialogs.closeAll()
			return h, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, next := tc.run(t)
			waitSessions(t, h, 0)
			waitForRelease(t, h)
			if g := h.srv.metrics.Snapshot().ActiveSessions; g != 0 {
				t.Errorf("session gauge = %d after teardown, want 0", g)
			}
			if next != nil {
				if code := next(); code != 200 {
					t.Errorf("next call after the teardown: %d, want 200 (slot leaked?)", code)
				}
			}
			assertNoCapRejects(t, h)
		})
	}
}

// assertNoCapRejects fails if a cap or rate rejection was counted: the
// leak cases must never have been refused.
func assertNoCapRejects(t *testing.T, h *harness) {
	t.Helper()
	got := h.srv.metrics.Snapshot().InviteRejects
	for _, r := range []inviteReject{rejectSessionCap, rejectInviteRate} {
		if got[r.String()] != 0 {
			t.Errorf("invite_rejects{%q} = %d, want 0", r, got[r.String()])
		}
	}
}

// ---------------------------------------------------------------------
// shield.invite_rate_limit
// ---------------------------------------------------------------------

func TestInviteRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		limit string
		want  int
	}{
		{"1/s", 1}, {"2/s", 1}, {"1000/s", 1}, {"3/m", 20}, {"7/m", 9}, {"1/m", 60}, {"1/h", 3600},
	} {
		rl, err := config.ParseRateLimit(tc.limit)
		if err != nil {
			t.Fatal(err)
		}
		if got := inviteRetryAfter(rl); got != tc.want {
			t.Errorf("inviteRetryAfter(%s) = %d, want %d", tc.limit, got, tc.want)
		}
	}
}

// Past the rate an admitted peer, client or switch, gets 503 with the
// seconds until a token is free; the refused INVITE holds no slot, a
// re-INVITE is not charged and nothing that was running ends.
func TestInviteRateLimit(t *testing.T) {
	h := startHarness(t, false)
	setShield(h, 0, "3/m")
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001") // a REGISTER is not charged
	var first *sip.Request
	var firstRes *sip.Response
	var firstRTP *net.UDPConn
	for i := 0; i < 3; i++ {
		invite, res, rtp := auditPhoneCall(t, h, phone)
		if i == 0 {
			first, firstRes, firstRTP = invite, res, rtp
		}
	}
	waitForDialog(t, h, fsip.CallID(first))
	inUse := portsInUse(h)

	// The bucket is empty: a re-INVITE still goes through.
	if _, re := auditPhoneReInvite(t, h, phone, first, firstRes, 2, phoneOfferSDP(auditUDPPort(firstRTP))); re.StatusCode != 200 {
		t.Fatalf("re-INVITE past the rate: %d, want 200", re.StatusCode)
	}
	// A client call and a switch-placed call are both refused.
	assertBusy(t, phoneInvite(t, h, phone), "20")
	assertBusy(t, h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)), "20")

	assertRejects(t, h, map[inviteReject]uint64{rejectInviteRate: 2})
	if n := h.srv.dialogs.sessionCount(); n != 3 {
		t.Errorf("sessions = %d, want the 3 admitted calls (a refused INVITE holds no slot)", n)
	}
	if n := portsInUse(h); n != inUse {
		t.Errorf("media ports in use = %d after the refusals, want %d", n, inUse)
	}
	for reason, n := range callsEnded(h) {
		if n != 0 {
			t.Errorf("calls_ended{%q} = %d: a refused INVITE is not a call that ended", reason, n)
		}
	}
	if got := h.fs.received(sip.INVITE); len(got) != 4 { // 3 calls + the re-INVITE
		t.Errorf("the switch saw %d INVITEs, want 4", len(got))
	}
}

// One INVITE costs one token however often it is retransmitted.
func TestInviteRateRetransmissionChargedOnce(t *testing.T) {
	h := startHarness(t, false)
	setShield(h, 0, "2/m")
	h.fs.setInviteHook(h.fs.silentHook())

	conn := auditUDP(t)
	raw := &client{transport: "udp", local: conn.LocalAddr().String()}
	invite := raw.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30500))
	pub, err := net.ResolveUDPAddr("udp", h.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := conn.WriteToUDP([]byte(invite.String()), pub); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	waitReceived(t, h.fs, sip.INVITE, 1)

	phone := newUDPClient(t)
	phoneUAC(t, h, phone, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30502)))
	waitReceived(t, h.fs, sip.INVITE, 2)

	assertBusy(t, phoneInvite(t, h, newUDPClient(t)), "30")
	assertRejects(t, h, map[inviteReject]uint64{rejectInviteRate: 1})
	if got := h.fs.received(sip.INVITE); len(got) != 2 {
		t.Errorf("the switch saw %d INVITEs, want 2", len(got))
	}
}

// invite_rate_limit is hot, and when both limits apply the session cap is
// the one reported (it is checked first, so it consumes no rate token).
func TestInviteRateHotAndOrder(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	setShield(h, 1, "1/m")
	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Fatalf("call 1: %d", code)
	}
	// Full: the cap answers, and spends no token.
	assertBusy(t, phoneInvite(t, h, phone), "5")
	assertRejects(t, h, map[inviteReject]uint64{rejectSessionCap: 1})
	setShield(h, 2, "1/m")
	assertBusy(t, phoneInvite(t, h, phone), "60")
	assertRejects(t, h, map[inviteReject]uint64{rejectSessionCap: 1, rejectInviteRate: 1})
	// Turning the rate off applies at once.
	setShield(h, 2, "")
	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Errorf("call after turning the rate limit off: %d", code)
	}
}

// ---------------------------------------------------------------------
// dialogTable unit tests
// ---------------------------------------------------------------------

func unitInvite(callID string) *sip.Request {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "2002", Host: "example.com"})
	from := &sip.FromHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", "t-"+callID)
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "2002", Host: "example.com"}, Params: sip.NewParams()})
	id := sip.CallIDHeader(callID)
	req.AppendHeader(&id)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	return req
}

func TestDialogTableBeginResults(t *testing.T) {
	m := NewMetrics()
	tab := newDialogTable(m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a, res := tab.begin(unitInvite("a"), planePublic, 2)
	if res != beginOK {
		t.Fatalf("a: %v", res)
	}
	if _, res := tab.begin(unitInvite("a"), planePublic, 2); res != beginMerged {
		t.Errorf("merged INVITE: %v, want beginMerged", res)
	}
	if n := tab.sessionCount(); n != 1 {
		t.Errorf("a merged INVITE took a slot: %d", n)
	}
	b, res := tab.begin(unitInvite("b"), planePublic, 2)
	if res != beginOK {
		t.Fatalf("b: %v", res)
	}
	if _, res := tab.begin(unitInvite("c"), planePublic, 2); res != beginFull {
		t.Errorf("c over the limit: %v, want beginFull", res)
	}
	if g := m.Snapshot().ActiveSessions; g != 2 {
		t.Errorf("gauge = %d, want 2", g)
	}
	a.end(endShutdown)
	a.end(endShutdown) // a second end frees nothing more
	if n := tab.sessionCount(); n != 1 {
		t.Errorf("sessions = %d after one end, want 1", n)
	}
	// limit <= 0 is unlimited.
	for i := 0; i < 20; i++ {
		if _, res := tab.begin(unitInvite("u"+strconv.Itoa(i)), planePublic, 0); res != beginOK {
			t.Fatalf("unlimited begin %d: %v", i, res)
		}
	}
	tab.close()
	if _, res := tab.begin(unitInvite("z"), planePublic, 2); res != beginClosed {
		t.Errorf("after close: %v, want beginClosed", res)
	}
	tab.closeAll()
	_ = b
	if n := tab.sessionCount(); n != 0 {
		t.Errorf("sessions = %d after closeAll, want 0", n)
	}
}

// Concurrent begin and end never exceed the limit and always return to
// zero. Run under -race.
func TestDialogTableSessionLimitConcurrent(t *testing.T) {
	const limit, workers, rounds = 5, 32, 300
	tab := newDialogTable(NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	var held, admitted, refused atomic.Int64
	var over atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				d, res := tab.begin(unitInvite(fmt.Sprintf("w%d-%d", w, i)), planePublic, limit)
				switch res {
				case beginOK:
					admitted.Add(1)
					if held.Add(1) > limit || tab.sessionCount() > limit {
						over.Store(true)
					}
					held.Add(-1)
					d.end(endShutdown)
				case beginFull:
					refused.Add(1)
				default:
					t.Errorf("unexpected result %v", res)
				}
			}
		}()
	}
	wg.Wait()
	if over.Load() {
		t.Error("the session count exceeded the limit")
	}
	if n := tab.sessionCount(); n != 0 {
		t.Errorf("sessions = %d after every dialog ended, want 0", n)
	}
	if admitted.Load() == 0 || admitted.Load()+refused.Load() != workers*rounds {
		t.Errorf("admitted %d, refused %d of %d", admitted.Load(), refused.Load(), workers*rounds)
	}
}
