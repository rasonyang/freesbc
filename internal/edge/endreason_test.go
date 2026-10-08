package edge

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// Why a call ended and why an INVITE was refused (issue #137): the "call
// ended" log line and freesbc_edge_calls_ended_total{reason} for every
// confirmed call, and freesbc_edge_invite_rejects_total{reason} for every
// final response the edge itself sends to an out-of-dialog INVITE.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// startHarnessRecorded is startHarness (plus a ws listener when webrtc is
// set) with the proxy's log kept for inspection.
func startHarnessRecorded(t *testing.T, webrtc bool) (*harness, *logRecorder) {
	t.Helper()
	pubWS := 0
	if webrtc {
		pubWS = freeTCPPort(t)
	}
	pubUDP, priv, up := freePort(t), freePort(t), freePort(t)
	mediaBase := nextMediaBase(t)
	rec := newLogRecorder()
	h := newHarnessLog(t, harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)},
		pubUDP, pubWS, 0, mediaBase, harnessCarrierSources), priv, rec)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.run()
	return h, rec
}

// callEndedLine waits for the "call ended" record of callID.
func callEndedLine(t *testing.T, rec *logRecorder, callID string) recordedLog {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range rec.snapshot() {
			if r.msg == "call ended" && r.attrs["sip_call_id"] == callID {
				return r
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no \"call ended\" line for %s", callID)
	return recordedLog{}
}

// callsEnded is the counter of every end reason.
func callsEnded(h *harness) map[string]uint64 { return h.srv.metrics.Snapshot().CallsEnded }

// assertEnded checks that callID's "call ended" line and the counters both
// carry want, and nothing else was counted.
func assertEnded(t *testing.T, h *harness, rec *logRecorder, callID string, want endReason, webrtc, carrier bool) {
	t.Helper()
	line := callEndedLine(t, rec, callID)
	if line.level.String() != "INFO" {
		t.Errorf("call ended logged at %s, want INFO", line.level)
	}
	if got := line.attrs["reason"]; got != want.String() {
		t.Errorf("call ended reason = %q, want %q", got, want)
	}
	if line.attrs["duration"] == "" {
		t.Error("call ended has no duration")
	}
	if got := line.attrs["webrtc"]; got != fmt.Sprint(webrtc) {
		t.Errorf("call ended webrtc = %q, want %v", got, webrtc)
	}
	if got := line.attrs["carrier"]; got != fmt.Sprint(carrier) {
		t.Errorf("call ended carrier = %q, want %v", got, carrier)
	}
	// The counter moves with the line, once.
	for reason, n := range callsEnded(h) {
		wantN := uint64(0)
		if reason == want.String() {
			wantN = 1
		}
		if n != wantN {
			t.Errorf("calls_ended{reason=%q} = %d, want %d", reason, n, wantN)
		}
	}
	n := 0
	for _, r := range rec.snapshot() {
		if r.msg == "call ended" && r.attrs["sip_call_id"] == callID {
			n++
		}
	}
	if n != 1 {
		t.Errorf("call ended logged %d times, want 1", n)
	}
}

// Every label of both counters exists from the start, at zero, and the
// sets are exactly the enums.
func TestEndAndRejectCountersStartAtZero(t *testing.T) {
	snap := NewMetrics().Snapshot()
	if len(snap.CallsEnded) != int(numEndReasons) || len(snap.InviteRejects) != int(numInviteRejects) {
		t.Fatalf("label sets: %d end reasons, %d reject reasons", len(snap.CallsEnded), len(snap.InviteRejects))
	}
	for r := endReason(0); r < numEndReasons; r++ {
		if n, ok := snap.CallsEnded[r.String()]; !ok || n != 0 || r.String() == "" {
			t.Errorf("calls_ended{%q} = %d, present %v; want 0, present", r.String(), n, ok)
		}
	}
	for r := inviteReject(0); r < numInviteRejects; r++ {
		if n, ok := snap.InviteRejects[r.String()]; !ok || n != 0 || r.String() == "" {
			t.Errorf("invite_rejects{%q} = %d, present %v; want 0, present", r.String(), n, ok)
		}
	}
}

// bye_caller: the caller (a phone) hangs up.
func TestEndReasonByeCaller(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	invite, res, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("BYE: %d", r.StatusCode)
	}
	assertEnded(t, h, rec, fsip.CallID(invite), endByeCaller, false, true)
}

// bye_callee: the switch, the callee of a phone's call, hangs up.
func TestEndReasonByeCallee(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
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
	assertEnded(t, h, rec, fsip.CallID(invite), endByeCallee, false, true)
}

// A call the switch placed: the switch is the caller, so its BYE is the
// caller's.
func TestEndReasonByeCallerOnSwitchPlacedCall(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
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
		t.Fatalf("BYE from the switch: %d", b.StatusCode)
	}
	assertEnded(t, h, rec, fsip.CallID(res), endByeCaller, false, false)
}

// bye_unanswered: the far side cannot be sent the BYE, so FreeSBC answers
// 200, re-sends it statelessly and ends the dialog.
func TestEndReasonByeUnanswered(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	phone := newUDPClient(t)
	invite, _, _ := auditPhoneCall(t, h, phone)
	tag := <-tags
	d := waitForDialog(t, h, fsip.CallID(invite))
	up := waitReceived(t, h.fs, sip.INVITE, 1)[0]
	drain(phone.inbound)
	// An address with no port: the forward fails before a byte leaves.
	h.srv.dialogs.mu.Lock()
	d.route.publicRemote = "127.0.0.1"
	h.srv.dialogs.mu.Unlock()
	if r := h.fs.inDialog(t, sip.BYE, up, tag); r.StatusCode != 200 {
		t.Fatalf("BYE from the switch: %d", r.StatusCode)
	}
	assertEnded(t, h, rec, fsip.CallID(invite), endByeUnanswered, false, true)
}

// rtp_silence: the watchdog reclaims a call that carries no media.
func TestEndReasonRTPSilence(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.srv.setRTPTimeout(time.Second)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	invite, _, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	assertEnded(t, h, rec, fsip.CallID(invite), endRTPSilence, false, true)
	// Both ends are told, and the line says why.
	h.fs.waitFor(sip.BYE, 1, 3*time.Second)
	found := false
	for _, r := range rec.snapshot() {
		if r.msg == "ending the call; sending BYE to both ends" && r.attrs["reason"] == "rtp_silence" {
			found = true
		}
	}
	if !found {
		t.Error("byeBothEnds did not log the rtp_silence reason")
	}
}

// rtp_silence on a browser leg, with the webrtc flag set.
func TestEndReasonRTPSilenceWebRTC(t *testing.T) {
	h, rec := startHarnessRecorded(t, true)
	h.srv.setRTPTimeout(time.Second)
	_, _, call, _ := placeBrowserCall(t, h, "ws", "active", "127.0.0.1")
	assertEnded(t, h, rec, fsip.CallID(call.res), endRTPSilence, true, false)
}

// dtls_failure: a browser whose DTLS certificate does not match the
// fingerprint it signalled never gets media, and the call ends.
func TestEndReasonDTLSFailure(t *testing.T) {
	h, rec := startHarnessRecorded(t, true)
	c := newWSClient(t)
	ruri := registerOver(t, h, c, h.publicWS, "1001")
	b := newFakeBrowser(t, "active")
	b.fpOverride = sha256Fingerprint([]byte("not the certificate"))
	calls := make(chan inboundBrowserCall, 1)
	browserAnswers(c, b, "127.0.0.1", calls)
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("FreeSWITCH -> browser INVITE: got %d, want 200", res.StatusCode)
	}
	h.fs.sendAckTo2xx(t, res)
	assertEnded(t, h, rec, fsip.CallID(res), endDTLSFailure, true, false)
	if snap := h.srv.metrics.Snapshot(); snap.WebRTCDTLSFailures != 1 {
		t.Errorf("dtls failure counter = %d, want 1", snap.WebRTCDTLSFailures)
	}
}

// reinvite_refused: a re-INVITE 2xx the edge cannot anchor ends the call.
func TestEndReasonReinviteRefused(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, func(req *sip.Request, tx sip.ServerTransaction) {
		body := fmt.Sprintf("v=0\r\no=FreeSWITCH 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 96\r\na=rtpmap:96 PCMU/8000\r\na=sendrecv\r\n", h.fs.rtpPort)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		_ = tx.Respond(res)
	}))
	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	<-tags
	waitForDialog(t, h, fsip.CallID(invite))
	h.fs.waitFor(sip.ACK, 1, 3*time.Second)
	auditPhoneReInvite(t, h, phone, invite, res, 2, phoneOfferSDP(auditUDPPort(phoneRTP)))
	assertEnded(t, h, rec, fsip.CallID(invite), endReinviteRefused, false, true)
	found := false
	for _, r := range rec.snapshot() {
		if r.msg == "ending the call; sending BYE to both ends" && r.attrs["reason"] == "reinvite_refused" {
			found = true
		}
	}
	if !found {
		t.Error("byeBothEnds did not log the reinvite_refused reason")
	}
}

// shutdown: closing the dialog table ends what is up.
func TestEndReasonShutdown(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	invite, _, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	h.srv.dialogs.close()
	h.srv.dialogs.closeAll()
	assertEnded(t, h, rec, fsip.CallID(invite), endShutdown, false, true)
}

// answer_timeout: the answer owed to a delayed offer never arrives.
func TestEndReasonAnswerTimeout(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.fs.setInviteHook(offerIn200(h.fs, "uas-ol-timeout", sdpWith(h.fs.rtpPort, "sendrecv")))
	h.srv.ackWait.Store(int64(600 * time.Millisecond))
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", "")
	call := phoneUAC(t, h, phone, invite)
	res := call.final200(t)
	assertEnded(t, h, rec, fsip.CallID(res), endAnswerTimeout, false, true)
}

// answer_unusable: the answer in the ACK cannot be anchored.
func TestEndReasonAnswerUnusable(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.fs.setInviteHook(offerIn200(h.fs, "uas-ol-bad", sdpWith(h.fs.rtpPort, "sendrecv")))
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", "")
	call := phoneUAC(t, h, phone, invite)
	res := call.final200(t)
	phoneAck(t, h, phone, invite, res, "not sdp\r\n")
	assertEnded(t, h, rec, fsip.CallID(res), endAnswerUnusable, false, true)
}

// Two teardown paths at once record exactly one reason: callers racing end
// directly, and a real BYE racing the silence watchdog.
func TestEndReasonRaceRecordsOne(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		h, rec := startHarnessRecorded(t, false)
		h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
		phone := newUDPClient(t)
		invite, _, _ := auditPhoneCall(t, h, phone)
		d := waitForDialog(t, h, fsip.CallID(invite))
		var wg sync.WaitGroup
		start := make(chan struct{})
		var mu sync.Mutex
		winners := 0
		for r := endReason(0); r < numEndReasons; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if d.end(r) {
					mu.Lock()
					winners++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if winners != 1 {
			t.Errorf("%d end() calls reported ending the dialog, want 1", winners)
		}
		line := callEndedLine(t, rec, fsip.CallID(invite))
		total := uint64(0)
		for reason, n := range callsEnded(h) {
			total += n
			if n == 1 && reason != line.attrs["reason"] {
				t.Errorf("counter %q moved but the line says %q", reason, line.attrs["reason"])
			}
		}
		if total != 1 {
			t.Errorf("calls_ended total = %d, want 1", total)
		}
	})

	t.Run("bye and watchdog", func(t *testing.T) {
		h, rec := startHarnessRecorded(t, false)
		h.srv.setRTPTimeout(time.Second)
		h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
		const n = 4
		type call struct {
			phone  *client
			invite *sip.Request
			res    *sip.Response
		}
		var calls []call
		for i := 0; i < n; i++ {
			phone := newUDPClient(t)
			invite, res, _ := auditPhoneCall(t, h, phone)
			waitForDialog(t, h, fsip.CallID(invite))
			calls = append(calls, call{phone, invite, res})
		}
		// The watchdog fires between 1.0 and 1.25 s after the call starts;
		// the BYEs straddle that window.
		var wg sync.WaitGroup
		for i, c := range calls {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(time.Duration(950+i*100) * time.Millisecond)
				c.phone.do(t, buildBye(c.phone, c.invite, c.res), h.publicUDP)
			}()
		}
		wg.Wait()
		reasons := map[string]bool{}
		for _, c := range calls {
			reasons[callEndedLine(t, rec, fsip.CallID(c.invite)).attrs["reason"]] = true
		}
		time.Sleep(300 * time.Millisecond)
		total := uint64(0)
		for _, v := range callsEnded(h) {
			total += v
		}
		lines := 0
		for _, r := range rec.snapshot() {
			if r.msg == "call ended" {
				lines++
			}
		}
		if total != n || lines != n {
			t.Errorf("%d calls ended: counters total %d, %d call ended lines", n, total, lines)
		}
		for r := range reasons {
			if r != "bye_caller" && r != "rtp_silence" {
				t.Errorf("unexpected reason %q", r)
			}
		}
	})
}

// An early dialog that never connects is not a call that ended.
func TestEarlyDialogEndIsNotACallEnded(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
		return true
	})
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30301))
	if res := phone.do(t, invite, h.publicUDP); res.StatusCode != 486 {
		t.Fatalf("got %d, want 486", res.StatusCode)
	}
	waitForRelease(t, h)
	for _, r := range rec.snapshot() {
		if r.msg == "call ended" {
			t.Errorf("an unanswered call logged call ended: %v", r.attrs)
		}
	}
	for reason, n := range callsEnded(h) {
		if n != 0 {
			t.Errorf("calls_ended{%q} = %d for a call that never connected", reason, n)
		}
	}
	// A relayed 486 is the switch's answer, not the edge's.
	assertRejects(t, h, nil)
}

// assertRejects checks the whole reject counter set: want's labels carry
// their count, every other label is zero.
func assertRejects(t *testing.T, h *harness, want map[inviteReject]uint64) {
	t.Helper()
	got := h.srv.metrics.Snapshot().InviteRejects
	for r := inviteReject(0); r < numInviteRejects; r++ {
		if got[r.String()] != want[r] {
			t.Errorf("invite_rejects{reason=%q} = %d, want %d", r, got[r.String()], want[r])
		}
	}
}

// waitRejects waits until the counter of r reaches n.
func waitRejects(t *testing.T, h *harness, r inviteReject, n uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.metrics.Snapshot().InviteRejects[r.String()] >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("invite_rejects{%q} never reached %d", r, n)
}

// shutting_down: an INVITE arriving once shutdown has begun.
func TestInviteRejectShuttingDown(t *testing.T) {
	h := startHarness(t, false)
	h.srv.dialogs.close()
	phone := newUDPClient(t)
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30302)), h.publicUDP)
	if res.StatusCode != 503 {
		t.Fatalf("got %d, want 503", res.StatusCode)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectShuttingDown: 1})
}

// media_failed: an offer with nothing to anchor is refused 488 once, even
// when the INVITE is retransmitted, and a re-INVITE refused the same way
// later is not an INVITE reject at all.
func TestInviteRejectMediaFailedCountedOnce(t *testing.T) {
	h := startHarness(t, false)
	conn := auditUDP(t)
	raw := &client{transport: "udp", local: conn.LocalAddr().String()}
	bad := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 96\r\na=rtpmap:96 G729/8000\r\n"
	invite := raw.buildInvite("1001", "2002", "example.com", bad)
	pub, err := net.ResolveUDPAddr("udp", h.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	// The same datagram three times: sipgo hands retransmissions to the
	// transaction, not to the handler. The raw client never ACKs, so the
	// 488 is retransmitted as well.
	for i := 0; i < 3; i++ {
		if _, err := conn.WriteToUDP([]byte(invite.String()), pub); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !auditRecvUntil(conn, 3*time.Second, func(b []byte) bool { return strings.HasPrefix(string(b), "SIP/2.0 488") }) {
		t.Fatal("no 488")
	}
	time.Sleep(1200 * time.Millisecond) // a retransmitted 488 (Timer G) too
	assertRejects(t, h, map[inviteReject]uint64{rejectMediaFailed: 1})

	// A re-INVITE the edge refuses with the same 488 is not counted.
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	call, res, rtp := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(call))
	_, reRes := auditPhoneReInvite(t, h, phone, call, res, 2, bad)
	if reRes.StatusCode != 488 {
		t.Fatalf("re-INVITE with nothing to anchor: got %d, want 488", reRes.StatusCode)
	}
	_ = rtp
	assertRejects(t, h, map[inviteReject]uint64{rejectMediaFailed: 1})
}

// port_exhausted: no media port is free.
func TestInviteRejectPortExhausted(t *testing.T) {
	h := startHarness(t, false)
	_, total := h.srv.pubPool.Stats()
	var held []interface{ Close() error }
	for i := 0; i < total; i++ {
		sess, err := h.srv.allocateRTP(&sdp.Session{Audio: &sdp.Audio{Address: mustAddr("127.0.0.1"), Port: 40000}}, netip.MustParseAddr("127.0.0.1"), srtpOff)
		if err != nil {
			break
		}
		held = append(held, sess)
	}
	defer func() {
		for _, s := range held {
			_ = s.Close()
		}
	}()
	phone := newUDPClient(t)
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30303)), h.publicUDP)
	if res.StatusCode != 503 {
		t.Fatalf("got %d, want 503", res.StatusCode)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectPortExhausted: 1})
}

// too_many_hops: Max-Forwards 0 on an INVITE.
func TestInviteRejectTooManyHops(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	invite := withMaxForwards(phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30304)), 0)
	if res := phone.do(t, invite, h.publicUDP); res.StatusCode != 483 {
		t.Fatalf("got %d, want 483", res.StatusCode)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectTooManyHops: 1})
}

// no_target: the switch calls a contact no client registered.
func TestInviteRejectNoTarget(t *testing.T) {
	h := startHarness(t, false)
	ruri := sip.Uri{User: "1001", Host: "127.0.0.1", Port: 5060}
	if res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)); res.StatusCode != 404 {
		t.Fatalf("got %d, want 404", res.StatusCode)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectNoTarget: 1})
}

// loop_detected: a second INVITE that merges with a call still being set
// up (same Call-ID and From tag, new branch) is refused 482, once.
func TestInviteRejectLoopDetected(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(h.fs.silentHook())
	phone := newUDPClient(t)
	first := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30305))
	_ = phoneUAC(t, h, phone, first.Clone())
	waitReceived(t, h.fs, sip.INVITE, 1)
	second := first.Clone()
	second.Via().Params.Add("branch", sip.GenerateBranchN(16))
	if res := phone.do(t, second, h.publicUDP); res.StatusCode != 482 {
		t.Fatalf("got %d, want 482", res.StatusCode)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectLoopDetected: 1})
}

// timeout: the INVITE's own budget runs out with only provisionals seen.
func TestInviteRejectTimeout(t *testing.T) {
	h := startHarness(t, false)
	h.srv.inviteBackstop.Store(int64(700 * time.Millisecond))
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		return h.fs.silentHook()(req, tx)
	})
	phone := newUDPClient(t)
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30306)), h.publicUDP)
	if res.StatusCode != 408 {
		t.Fatalf("got %d, want 408", res.StatusCode)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectTimeout: 1})
}

// early_cap: the unanswered-call cap refuses the extra INVITE, once, though
// its 503 is retransmitted until ACKed.
func TestInviteRejectEarlyCap(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	h.fs.setInviteHook(h.fs.silentHook())
	c := auditUDP(t)
	port := auditUDPPort(c)
	if _, err := h.srv.loc.Put(Binding{Token: "cap-token", AOR: "1001@example.com", User: "1001",
		Transport: "udp", Source: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)),
		ExpiresAt: time.Now().Add(time.Hour), CallID: "cap-reg"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxEarlyPerSource+1; i++ {
		body := phoneOfferSDP(31100 + 2*i)
		auditRawRequest(t, c, h.publicUDP, fmt.Sprintf("INVITE sip:2002@example.com SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-cap-%d;rport\r\n"+
			"Max-Forwards: 70\r\nFrom: <sip:1001@example.com>;tag=cap%d\r\nTo: <sip:2002@example.com>\r\n"+
			"Call-ID: cap-%d\r\nCSeq: 1 INVITE\r\nContact: <sip:1001@127.0.0.1:%d>\r\n"+
			"Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s",
			port, i, i, i, port, len(body), body))
		time.Sleep(5 * time.Millisecond)
	}
	waitRejects(t, h, rejectEarlyCap, 1)
	time.Sleep(1500 * time.Millisecond) // the 503 is retransmitted meanwhile
	assertRejects(t, h, map[inviteReject]uint64{rejectEarlyCap: 1})
}

// upstream_failed: every switch attempt fails at the transport.
func TestInviteRejectUpstreamFailed(t *testing.T) {
	// A non-loopback switch address the socket cannot reach: the send
	// fails at once (see upstreams_test.go).
	h, _ := startHarnessSwitches(t, []string{"192.0.2.1:5060"})
	phone := newUDPClient(t)
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30307)), h.publicUDP)
	if res.StatusCode != 503 {
		t.Fatalf("got %d, want 503", res.StatusCode)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectUpstreamFailed: 1})
}
