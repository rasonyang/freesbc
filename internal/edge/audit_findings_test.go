package edge

// Phase 3 audit tests for internal/edge (docs/audit/phase3/edge.md). Each
// test asserts the behaviour the RFC or the documented invariant requires;
// a FAIL confirms the Phase 2 finding named in its `// audit:` marker, a
// PASS refutes it. None of these tests is meant to be made green by
// editing the test.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// auditSeqIs matches an RTP packet by its sequence number.
func auditSeqIs(seq uint16) func([]byte) bool {
	return func(b []byte) bool { return len(b) >= 12 && binary.BigEndian.Uint16(b[2:4]) == seq }
}

// audit: P2-EDG-001
// The public RTP leg must not hand the stream to whichever source sends to
// the SBC port first (docs/edge.md:67 "strict source latching resists
// off-path hijacking"). An attacker on another port sends one packet before
// the phone does; afterwards FreeSWITCH's audio must not reach the attacker
// and the phone's audio must still reach FreeSWITCH.
func TestAuditLooseLatchHijack(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	fsRTP, err := net.ListenUDP("udp", auditLocalAddr(h.fs.rtpPort))
	if err != nil {
		t.Fatal(err)
	}
	defer fsRTP.Close()

	_, res, phoneRTP := auditPhoneCall(t, h, phone)
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}
	upInv := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(upInv) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs", len(upInv))
	}
	up, err := parseLabSDP(upInv[0].Body())
	if err != nil {
		t.Fatal(err)
	}
	sbcPublic := auditLocalAddr(answer.Audio.Port)
	sbcPrivate := auditLocalAddr(up.Audio.Port)

	// The attacker's single packet arrives before any phone RTP.
	attacker := auditUDP(t)
	for i := 0; i < 3; i++ {
		_, _ = attacker.WriteToUDP(rtpPacket(0, 7000+uint16(i), 160), sbcPublic)
	}
	time.Sleep(100 * time.Millisecond)

	// FreeSWITCH talks; who hears it?
	go func() {
		for i := 0; i < 20; i++ {
			_, _ = fsRTP.WriteToUDP(rtpPacket(0, 8000, 160), sbcPrivate)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	if auditRecvUntil(attacker, 1500*time.Millisecond, auditSeqIs(8000)) {
		t.Errorf("P2-EDG-001 confirmed: an off-path source that sent first to public port %d receives FreeSWITCH's audio", answer.Audio.Port)
	}

	// The real phone now talks; does FreeSWITCH hear it?
	go func() {
		for i := 0; i < 20; i++ {
			_, _ = phoneRTP.WriteToUDP(rtpPacket(0, 9000, 160), sbcPublic)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	if !auditRecvUntil(fsRTP, 1500*time.Millisecond, auditSeqIs(9000)) {
		t.Errorf("P2-EDG-001 confirmed: the signalled phone's RTP is dropped after the attacker latched the public leg")
	}
}

// audit: P2-EDG-005
// RFC 3261 §12/§12.2.2: a BYE whose tags match no dialog is answered 481 by
// the UAS and ends nothing. A third party that knows only the Call-ID sends
// a BYE with invented tags; the call must stay up.
func TestAuditByeWrongTagsTearsDownCall(t *testing.T) {
	h := startHarness(t, false)
	var mu sync.Mutex
	var fsTag string
	auditSwapFakeSwitch(t, h, func(f *fakeSwitch, req *sip.Request, tx sip.ServerTransaction) {
		mu.Lock()
		want := fsTag
		mu.Unlock()
		// The switch is the UAS of this call: its own tag is the BYE's To tag.
		if got, _ := req.To().Params.Get("tag"); got != want {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))

	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	mu.Lock()
	fsTag = <-tags
	mu.Unlock()
	waitForDialog(t, h, fsip.CallID(invite))

	attacker := newUDPClient(t)
	bye := buildBye(attacker, invite, res)
	bye.From().Params.Remove("tag")
	bye.From().Params.Add("tag", "forged-from")
	bye.To().Params.Remove("tag")
	bye.To().Params.Add("tag", "forged-to")
	byeRes := attacker.do(t, bye, h.publicUDP)
	t.Logf("forged BYE answered %d", byeRes.StatusCode)

	time.Sleep(300 * time.Millisecond)
	if n := h.srv.ActiveCalls(); n != 1 {
		t.Errorf("P2-EDG-005 confirmed: after a BYE with forged tags (far end answered %d) ActiveCalls = %d, want 1", byeRes.StatusCode, n)
	}
	answer, _ := parseLabSDP(res.Body())
	fsRTP, err := net.ListenUDP("udp", auditLocalAddr(h.fs.rtpPort))
	if err != nil {
		t.Fatal(err)
	}
	defer fsRTP.Close()
	if !relayReaches(t, phoneRTP, auditLocalAddr(answer.Audio.Port), fsRTP, rtpPacket(0, 4242, 160)) {
		t.Errorf("P2-EDG-005 confirmed: media no longer relayed after a forged-tag BYE")
	}
}

// audit: P2-EDG-002
// Request metrics are keyed by the method string the client sent, before
// the shield. Distinct invented methods must not grow the map without
// bound (the known-method set times the transports is bounded).
func TestAuditMethodNameMetricsUnbounded(t *testing.T) {
	h := startHarness(t, false)
	c := auditUDP(t)
	dst, err := net.ResolveUDPAddr("udp", h.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	const n = 300
	port := auditUDPPort(c)
	for i := 0; i < n; i++ {
		m := fmt.Sprintf("AUDIT%04d", i)
		msg := fmt.Sprintf("%s sip:x@127.0.0.1 SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-audit-%d;rport\r\n"+
			"Max-Forwards: 70\r\nFrom: <sip:a@127.0.0.1>;tag=a%d\r\nTo: <sip:x@127.0.0.1>\r\n"+
			"Call-ID: audit-method-%d\r\nCSeq: 1 %s\r\nContent-Length: 0\r\n\r\n", m, port, i, i, i, m)
		if _, err := c.WriteToUDP([]byte(msg), dst); err != nil {
			t.Fatal(err)
		}
		if i%50 == 49 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	var keys int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		keys = len(h.srv.metrics.Snapshot().RequestsIn)
		if keys >= n {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("RequestsIn has %d keys after %d distinct invented methods", keys, n)
	if keys > 16 {
		t.Errorf("P2-EDG-002 confirmed: metrics RequestsIn grew to %d keys from %d attacker-chosen method names", keys, n)
	}
}

// audit: P2-EDG-004
// RFC 3261 §16.7 step 10 / §13.3.1.4, RFC 6026 §7.2: a proxy forwards every
// 2xx retransmission, because the UAS retransmits its 200 until it sees an
// ACK and the proxy's server transaction does not. The phone here never
// ACKs; FreeSWITCH retransmits its 200 twice. The phone must see more than
// one 200.
func TestAuditRetransmitted2xxRelayed(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
		retx := res.Clone()
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = h.fs.srv.TransportLayer().WriteMsg(retx)
			time.Sleep(time.Second)
			_ = h.fs.srv.TransportLayer().WriteMsg(retx)
		}()
		return true
	})

	c := auditUDP(t)
	dst, _ := net.ResolveUDPAddr("udp", h.publicUDP)
	port := auditUDPPort(c)
	body := phoneOfferSDP(30777)
	msg := fmt.Sprintf("INVITE sip:2002@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-audit-retx-%d;rport\r\n"+
		"Max-Forwards: 70\r\nFrom: <sip:1001@example.com>;tag=audretx\r\nTo: <sip:2002@example.com>\r\n"+
		"Call-ID: audit-retx-%d\r\nCSeq: 1 INVITE\r\nContact: <sip:1001@127.0.0.1:%d>\r\n"+
		"Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s",
		port, time.Now().UnixNano(), time.Now().UnixNano(), port, len(body), body)
	if _, err := c.WriteToUDP([]byte(msg), dst); err != nil {
		t.Fatal(err)
	}
	oks := 0
	buf := make([]byte, 8192)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if bytes.HasPrefix(buf[:n], []byte("SIP/2.0 200")) {
			oks++
		}
	}
	t.Logf("phone received %d copies of the 200 (FreeSWITCH sent 3)", oks)
	if oks < 2 {
		t.Errorf("P2-EDG-004 confirmed: FreeSWITCH retransmitted its 200 twice but the unACKing phone saw %d 200(s); retransmissions are dropped once the client transaction is terminated", oks)
	}
}

// audit: P2-EDG-006
// RFC 3261 §13.2.2.4 / §19.3, RFC 3264 §6: each early dialog's answer is its
// own. FreeSWITCH (standing in for a forking proxy) sends 183+SDP from fork
// A (port X) and then 200+SDP from fork B (port Y). The confirmed dialog is
// fork B's, so the phone's media must go to Y.
func TestAuditForked2xxMediaFollowsAnswer(t *testing.T) {
	h := startHarness(t, false)
	forkA := auditUDP(t)
	forkB := auditUDP(t)
	bodyOn := func(port int) []byte {
		return []byte(fmt.Sprintf("v=0\r\no=fork 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n", port))
	}
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		early := sip.NewResponseFromRequest(req, 183, "Session Progress", bodyOn(auditUDPPort(forkA)))
		early.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		early.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "forkA", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		early.To().Params.Add("tag", "fork-a")
		_ = tx.Respond(early)
		time.Sleep(100 * time.Millisecond)
		ok := sip.NewResponseFromRequest(req, 200, "OK", bodyOn(auditUDPPort(forkB)))
		ok.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		ok.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "forkB", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		ok.To().Params.Add("tag", "fork-b")
		_ = tx.Respond(ok)
		return true
	})
	phone := newUDPClient(t)
	_, res, phoneRTP := auditPhoneCall(t, h, phone)
	if tag, _ := res.To().Params.Get("tag"); tag != "fork-b" {
		t.Fatalf("phone's 200 carries To tag %q, want fork-b", tag)
	}
	answer, _ := parseLabSDP(res.Body())
	sbcPublic := auditLocalAddr(answer.Audio.Port)
	go func() {
		for i := 0; i < 25; i++ {
			_, _ = phoneRTP.WriteToUDP(rtpPacket(0, 5100, 160), sbcPublic)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	gotB := auditRecvUntil(forkB, 1500*time.Millisecond, auditSeqIs(5100))
	gotA := auditRecvUntil(forkA, 200*time.Millisecond, auditSeqIs(5100))
	t.Logf("phone RTP reached fork A=%v fork B=%v", gotA, gotB)
	if !gotB {
		t.Errorf("P2-EDG-006 confirmed: the dialog was confirmed by fork B's 200 but media is sent to fork A's 183 address (reached A=%v)", gotA)
	}
}

// audit: P2-EDG-011
// docs/edge.md:70 and RFC 5763 §5: a re-offer toward a WebRTC browser must
// describe the same DTLS-SRTP/ICE stream. FreeSWITCH re-INVITEs a browser
// call; the offer the browser receives must still be UDP/TLS/RTP/SAVPF with
// a fingerprint and ICE credentials.
func TestAuditReInviteTowardBrowserKeepsDTLS(t *testing.T) {
	h := startHarness(t, true)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	browser := newWSClient(t)
	invite := browser.buildInvite("1001", "2002", "example.com", browserOfferSDP(51234))
	res := browser.do(t, invite, h.publicWS)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	sendAck(t, browser, invite, res, h.publicWS)
	tag := <-tags
	upInv := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	waitForDialog(t, h, fsip.CallID(invite))
	drain(browser.inbound)

	reOffer := strings.Replace(h.fs.answerSDP(upInv[0]), "a=sendrecv", "a=sendonly", 1)
	reRes := auditInDialogWithBody(t, h.fs, sip.INVITE, upInv[0], tag, 2, reOffer)
	t.Logf("FreeSWITCH re-INVITE answered %d", reRes.StatusCode)

	var got *sip.Request
	deadline := time.After(3 * time.Second)
	for got == nil {
		select {
		case r := <-browser.inbound:
			if r.Method == sip.INVITE {
				got = r
			}
		case <-deadline:
			t.Fatal("the browser never received the re-INVITE")
		}
	}
	body := string(got.Body())
	var missing []string
	for _, want := range []string{"UDP/TLS/RTP/SAVPF", "a=fingerprint:", "a=ice-ufrag:", "a=ice-pwd:"} {
		if !strings.Contains(body, want) {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		t.Errorf("P2-EDG-011 confirmed: re-offer toward the browser lacks %v:\n%s", missing, body)
	}
}

// audit: P2-EDG-012
// RFC 3264 §8.3.1: a re-offer may move the media port and the answerer
// must send to the new one. FreeSWITCH moves its RTP to a new port by
// re-INVITE; the phone's audio must follow.
func TestAuditReInviteNewPortApplied(t *testing.T) {
	h := startHarness(t, false)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	fsRTP, err := net.ListenUDP("udp", auditLocalAddr(h.fs.rtpPort))
	if err != nil {
		t.Fatal(err)
	}
	defer fsRTP.Close()
	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	tag := <-tags
	waitForDialog(t, h, fsip.CallID(invite))
	upInv := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	answer, _ := parseLabSDP(res.Body())
	up, _ := parseLabSDP(upInv[0].Body())
	sbcPublic, sbcPrivate := auditLocalAddr(answer.Audio.Port), auditLocalAddr(up.Audio.Port)

	// Establish both latches on the original addresses.
	if !relayReaches(t, phoneRTP, sbcPublic, fsRTP, rtpPacket(0, 100, 160)) {
		t.Fatal("phone → FreeSWITCH media never flowed")
	}
	if !relayReaches(t, fsRTP, sbcPrivate, phoneRTP, rtpPacket(0, 200, 160)) {
		t.Fatal("FreeSWITCH → phone media never flowed")
	}

	newFS := auditUDP(t)
	auditPhoneAnswers(phone, auditUDPPort(phoneRTP), nil)
	reOffer := strings.Replace(phoneOfferSDP(auditUDPPort(newFS)), "o=phone 1 1", "o=FreeSWITCH 1 2", 1)
	reRes := auditInDialogWithBody(t, h.fs, sip.INVITE, upInv[0], tag, 2, reOffer)
	if reRes.StatusCode != 200 {
		t.Fatalf("re-INVITE from FreeSWITCH: got %d", reRes.StatusCode)
	}
	// FreeSWITCH now sends from, and expects media on, the new port.
	go func() {
		for i := 0; i < 20; i++ {
			_, _ = newFS.WriteToUDP(rtpPacket(0, 300, 160), sbcPrivate)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	fromNew := auditRecvUntil(phoneRTP, time.Second, auditSeqIs(300))
	go func() {
		for i := 0; i < 20; i++ {
			_, _ = phoneRTP.WriteToUDP(rtpPacket(0, 400, 160), sbcPublic)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	toNew := auditRecvUntil(newFS, time.Second, auditSeqIs(400))
	t.Logf("after the re-INVITE: new-port RTP reaches phone=%v, phone RTP reaches new port=%v", fromNew, toNew)
	if !toNew || !fromNew {
		t.Errorf("P2-EDG-012 confirmed: a re-INVITE that moved FreeSWITCH's media to port %d was not applied (to new=%v, from new=%v)",
			auditUDPPort(newFS), toNew, fromNew)
	}
}

// audit: P2-EDG-013
// RFC 3261 §13.3.1.4 / §17.1.1.3: a 2xx to a re-INVITE must be ACKed or it
// is retransmitted and the UAS ends the call. FreeSWITCH answers the
// phone's re-INVITE with a 200 the SBC cannot anchor (a renumbered payload
// type); whatever the phone is told, FreeSWITCH must get its ACK.
func TestAuditReInvite2xxUnanchorableIsACKed(t *testing.T) {
	h := startHarness(t, false)
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
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("initial ACK: FreeSWITCH saw %d", len(acks))
	}
	_, reRes := auditPhoneReInvite(t, h, phone, invite, res, 2, phoneOfferSDP(auditUDPPort(phoneRTP)))
	t.Logf("phone's re-INVITE answered %d", reRes.StatusCode)

	deadline := time.Now().Add(3 * time.Second)
	acked := false
	for time.Now().Before(deadline) && !acked {
		for _, a := range h.fs.received(sip.ACK) {
			if a.CSeq() != nil && a.CSeq().SeqNo == 2 {
				acked = true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !acked {
		t.Errorf("P2-EDG-013 confirmed: FreeSWITCH's 200 to the re-INVITE (unanchorable SDP) was never ACKed; the phone got %d", reRes.StatusCode)
	}
}

// audit: P2-EDG-032
// When the media watchdog ends a call, both endpoints still believe the
// dialog is up. The SBC must tell them (BYE), or FreeSWITCH keeps a channel
// and its later BYE gets 481.
func TestAuditMediaTimeoutSendsBye(t *testing.T) {
	h := startHarness(t, false)
	auditReplaceConfig(h, func(c *config.Config) { c.Listen.Media.RTPTimeout = config.Duration(time.Second) })
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	invite, _, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	drain(phone.inbound)

	// No RTP at all: the watchdog fires after ~1 s.
	deadline := time.Now().Add(6 * time.Second)
	for h.srv.ActiveCalls() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.srv.ActiveCalls() != 0 {
		t.Fatal("the media watchdog never ended the call")
	}
	fsBye := len(h.fs.waitFor(sip.BYE, 1, 2*time.Second))
	phoneBye := false
	timeout := time.After(time.Second)
loop:
	for {
		select {
		case r := <-phone.inbound:
			if r.Method == sip.BYE {
				phoneBye = true
				break loop
			}
		case <-timeout:
			break loop
		}
	}
	if fsBye == 0 || !phoneBye {
		t.Errorf("P2-EDG-032 confirmed: media timeout ended the call silently (BYE to FreeSWITCH: %d, BYE to phone: %v)", fsBye, phoneBye)
	}
}

// audit: P2-EDG-018
// RFC 3261 §13.2.2.4: the ACK for a 2xx must reach the UAS. FreeSWITCH ACKs
// the moment it receives the relayed 200; if the SBC relays before it
// records the dialog, that ACK finds no route and is dropped. Repeated
// FreeSWITCH→phone calls count ACKs that never reach the phone.
func TestAuditAckRacesCommit(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	phoneRTP := auditUDP(t)
	auditPhoneAnswers(phone, auditUDPPort(phoneRTP), nil)

	const rounds = 20
	missed := 0
	for i := 0; i < rounds; i++ {
		drain(phone.inbound)
		res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
		if res.StatusCode != 200 {
			t.Fatalf("round %d: inbound INVITE got %d", i, res.StatusCode)
		}
		h.fs.sendAckTo2xx(t, res) // immediately, as a real switch does
		gotAck := false
		timeout := time.After(time.Second)
	wait:
		for {
			select {
			case r := <-phone.inbound:
				if r.Method == sip.ACK {
					gotAck = true
					break wait
				}
			case <-timeout:
				break wait
			}
		}
		if !gotAck {
			missed++
		}
		waitForDialog(t, h, fsip.CallID(res))
		if b := h.fs.uacBye(t, res); b.StatusCode != 200 {
			t.Logf("round %d BYE: %d", i, b.StatusCode)
		}
		waitForRelease(t, h)
	}
	t.Logf("%d of %d ACKs never reached the phone", missed, rounds)
	if missed > 0 {
		t.Errorf("P2-EDG-018 confirmed: %d of %d immediate ACKs from FreeSWITCH were lost", missed, rounds)
	}
}
