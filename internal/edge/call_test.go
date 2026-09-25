package edge

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// buildInvite assembles an INVITE the way a phone does.
func (c *client) buildInvite(from, to, domain, body string) *sip.Request {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: to, Host: domain})
	f := &sip.FromHeader{Address: sip.Uri{User: from, Host: domain}, Params: sip.NewParams()}
	f.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(f)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: to, Host: domain}, Params: sip.NewParams()})
	callID := sip.CallIDHeader(fmt.Sprintf("call-%s-%d", c.transport, time.Now().UnixNano()))
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: c.contactURI(from)})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0",
		Transport: strings.ToUpper(c.transport), Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	if c.transport == "udp" {
		via.Params.Add("rport", "")
	}
	req.PrependHeader(via)
	req.SetBody([]byte(body))
	return req
}

// phoneOfferSDP is a plain SIP hardphone's offer: PCMU/PCMA plus RFC 4733
// DTMF, media on rtpPort.
func phoneOfferSDP(rtpPort int) string {
	return fmt.Sprintf("v=0\r\no=phone 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
		"m=audio %d RTP/AVP 0 8 101\r\n"+
		"a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"+
		"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=sendrecv\r\n", rtpPort)
}

// browserOfferSDP is what sip.js offers: DTLS-SRTP, ICE, rtcp-mux, opus.
func browserOfferSDP(rtpPort int) string {
	return fmt.Sprintf("v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"+
		"m=audio %d UDP/TLS/RTP/SAVPF 111 0 8 110\r\n"+
		"c=IN IP4 192.168.44.44\r\n"+
		"a=rtcp:%d IN IP4 192.168.44.44\r\n"+
		"a=ice-ufrag:F7gI\r\na=ice-pwd:x9cmlYzichV2XlhiMu8gAA\r\n"+
		"a=candidate:1 1 UDP 2130706431 192.168.44.44 %d typ host\r\n"+
		"a=candidate:2 1 UDP 1694498815 203.0.113.99 %d typ srflx raddr 192.168.44.44 rport %d\r\n"+
		"a=fingerprint:sha-256 6B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08\r\n"+
		"a=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\n"+
		"a=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\n"+
		"a=rtpmap:110 telephone-event/48000\r\na=sendrecv\r\n",
		rtpPort, rtpPort+1, rtpPort, rtpPort, rtpPort)
}

// rtpPacket builds a minimal valid RTP packet.
func rtpPacket(pt uint8, seq uint16, payload int) []byte {
	p := make([]byte, 12+payload)
	p[0] = 0x80
	p[1] = pt
	binary.BigEndian.PutUint16(p[2:4], seq)
	binary.BigEndian.PutUint32(p[4:8], uint32(seq)*160)
	binary.BigEndian.PutUint32(p[8:12], 0x11223344)
	return p
}

// TestCaseB_UDPCallWithRTP is acceptance criteria 4, 6, 7, 8, 9 and 10 for
// a plain SIP phone: signaling proxied, media anchored, PCMU and DTMF
// passed through untranscoded, and neither side ever told the other's
// address.
func TestCaseB_UDPCallWithRTP(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	// The phone's own media socket.
	phoneRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer phoneRTP.Close()
	phonePort := phoneRTP.LocalAddr().(*net.UDPAddr).Port

	// FreeSWITCH's media socket, on the port its answer will advertise.
	fsRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: h.fs.rtpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer fsRTP.Close()

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(phonePort))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}

	// --- what FreeSWITCH was offered ---
	invites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invites) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs", len(invites))
	}
	upstream, err := parseLabSDP(invites[0].Body())
	if err != nil {
		t.Fatalf("upstream offer unparseable: %v\n%s", err, invites[0].Body())
	}
	// Acceptance 9: FreeSWITCH must never be pointed at the phone.
	if upstream.Audio.Port == phonePort {
		t.Error("upstream offer advertises the phone's own RTP port — media would bypass the SBC")
	}
	if privRange := h.store.Current().RTP.Private; upstream.Audio.Port < privRange.PortMin || upstream.Audio.Port > privRange.PortMax {
		t.Errorf("upstream media port %d is outside the private pool %d-%d",
			upstream.Audio.Port, privRange.PortMin, privRange.PortMax)
	}
	// Payload numbers and DTMF must survive verbatim: the proxy does not
	// transcode, so both legs must agree on the numbers on the wire.
	if got := sdp.Describe(upstream.Audio.Codecs); !strings.Contains(got, "0 PCMU/8000") ||
		!strings.Contains(got, "8 PCMA/8000") || !strings.Contains(got, "101 telephone-event/8000") {
		t.Errorf("upstream codec list changed: %s", got)
	}
	// The Contact FreeSWITCH sees must be the SBC's, or in-dialog requests
	// would bypass it entirely.
	if c, ok := fsip.ContactURI(invites[0]); !ok || c.Port == 0 || c.Host != h.srv.topo.private.advIP.String() {
		t.Errorf("upstream Contact = %v, want the SBC's private address", c)
	}
	// Record-Route must be present, and doubled: the two sides of this
	// proxy speak different transports.
	if rr := invites[0].GetHeaders("Record-Route"); len(rr) < 2 {
		t.Errorf("Record-Route count = %d, want 2 (RFC 5658 double record-route)", len(rr))
	}

	// --- what the phone was answered ---
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatalf("answer unparseable: %v\n%s", err, res.Body())
	}
	// Acceptance 10: the phone must never learn FreeSWITCH's media port.
	if answer.Audio.Port == h.fs.rtpPort {
		t.Error("the phone was given FreeSWITCH's own RTP port")
	}
	if pubRange := h.store.Current().RTP.Public; answer.Audio.Port < pubRange.PortMin || answer.Audio.Port > pubRange.PortMax {
		t.Errorf("public media port %d is outside the public pool %d-%d",
			answer.Audio.Port, pubRange.PortMin, pubRange.PortMax)
	}
	if answer.Audio.Address.String() != "127.0.0.1" {
		t.Errorf("answer c= = %v", answer.Audio.Address)
	}
	// PCMU survived; so did DTMF at the phone's own payload number.
	if got := sdp.Describe(answer.Audio.Codecs); !strings.Contains(got, "0 PCMU/8000") ||
		!strings.Contains(got, "101 telephone-event/8000") {
		t.Errorf("answer codec list = %s", got)
	}

	// --- bidirectional media through the SBC ---
	publicPort := answer.Audio.Port
	privatePort := upstream.Audio.Port
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: publicPort}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: privatePort}

	// Phone → SBC → FreeSWITCH (a PCMU packet), and the DTMF payload type
	// right behind it, proving RFC 4733 traverses the relay untouched.
	audio := rtpPacket(0, 100, 160)
	dtmf := rtpPacket(101, 101, 4)
	if !relayReaches(t, phoneRTP, sbcPublic, fsRTP, audio) {
		t.Fatal("phone → FreeSWITCH audio never arrived")
	}
	if !relayReaches(t, phoneRTP, sbcPublic, fsRTP, dtmf) {
		t.Fatal("phone → FreeSWITCH DTMF never arrived")
	}
	// FreeSWITCH → SBC → phone.
	back := rtpPacket(0, 200, 160)
	if !relayReaches(t, fsRTP, sbcPrivate, phoneRTP, back) {
		t.Fatal("FreeSWITCH → phone audio never arrived")
	}

	// --- ACK must reach FreeSWITCH ---
	sendAck(t, phone, invite, res, h.publicUDP)
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Errorf("FreeSWITCH saw %d ACKs, want 1", len(acks))
	}

	// --- teardown releases everything (acceptance 11 / case E) ---
	if h.srv.ActiveCalls() != 1 {
		t.Fatalf("active calls = %d, want 1", h.srv.ActiveCalls())
	}
	bye := buildBye(phone, invite, res)
	if r := phone.do(t, bye, h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	if byes := h.fs.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
		t.Errorf("FreeSWITCH saw %d BYEs, want 1", len(byes))
	}
	waitForRelease(t, h)
}

// relayReaches sends pkt from `from` to the SBC socket `via` and reports
// whether it came out at `to`. It retries: the far side's latch may not
// have been armed by its own first packet yet.
func relayReaches(t *testing.T, from *net.UDPConn, via *net.UDPAddr, to *net.UDPConn, pkt []byte) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 2000)
	for time.Now().Before(deadline) {
		if _, err := from.WriteToUDP(pkt, via); err != nil {
			t.Fatal(err)
		}
		_ = to.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, _, err := to.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if string(buf[:n]) == string(pkt) {
			return true
		}
	}
	return false
}

// sendAck sends the 2xx ACK, which is a separate end-to-end transaction.
func sendAck(t *testing.T, c *client, invite *sip.Request, res *sip.Response, dest string) {
	t.Helper()
	ack := sip.NewRequest(sip.ACK, invite.Recipient)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0",
		Transport: strings.ToUpper(c.transport), Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	ack.PrependHeader(via)
	sip.CopyHeaders("From", invite, ack)
	sip.CopyHeaders("Call-ID", invite, ack)
	ack.AppendHeader(sip.HeaderClone(res.To()))
	ack.AppendHeader(&sip.CSeqHeader{SeqNo: invite.CSeq().SeqNo, MethodName: sip.ACK})
	mf := sip.MaxForwardsHeader(70)
	ack.AppendHeader(&mf)
	copyRouteFromRecordRoute(res, ack)
	ack.SetTransport(strings.ToUpper(c.transport))
	ack.SetDestination(dest)
	if err := c.cli.WriteRequest(ack); err != nil {
		t.Fatalf("send ACK: %v", err)
	}
}

// buildBye assembles an in-dialog BYE, routed by the Record-Route set the
// proxy inserted — which is the mechanism that keeps FreeSBC on the path.
func buildBye(c *client, invite *sip.Request, res *sip.Response) *sip.Request {
	bye := sip.NewRequest(sip.BYE, invite.Recipient)
	sip.CopyHeaders("From", invite, bye)
	sip.CopyHeaders("Call-ID", invite, bye)
	bye.AppendHeader(sip.HeaderClone(res.To()))
	bye.AppendHeader(&sip.CSeqHeader{SeqNo: invite.CSeq().SeqNo + 1, MethodName: sip.BYE})
	mf := sip.MaxForwardsHeader(70)
	bye.AppendHeader(&mf)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0",
		Transport: strings.ToUpper(c.transport), Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	bye.PrependHeader(via)
	copyRouteFromRecordRoute(res, bye)
	return bye
}

// copyRouteFromRecordRoute turns the response's Record-Route set into the
// UAC's Route set. RFC 3261 §12.1.2: the UAC reverses the order.
func copyRouteFromRecordRoute(res *sip.Response, req *sip.Request) {
	rrs := res.GetHeaders("Record-Route")
	for i := len(rrs) - 1; i >= 0; i-- {
		rr, ok := rrs[i].(*sip.RecordRouteHeader)
		if !ok {
			continue
		}
		req.AppendHeader(&sip.RouteHeader{Address: rr.Address})
	}
}

// waitForRelease asserts every media port went back to its pool.
func waitForRelease(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pubInUse, _ := h.srv.pubPool.Stats()
		privInUse, _ := h.srv.privPool.Stats()
		if pubInUse == 0 && privInUse == 0 && h.srv.ActiveCalls() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	pubInUse, _ := h.srv.pubPool.Stats()
	privInUse, _ := h.srv.privPool.Stats()
	t.Fatalf("resources leaked after teardown: public=%d private=%d calls=%d",
		pubInUse, privInUse, h.srv.ActiveCalls())
}

// TestCaseD_WebRTCCallSDP is acceptance criterion 5 at the signaling
// layer: a browser's DTLS-SRTP offer over WebSocket becomes a plain RTP
// offer upstream, and the browser gets a proper ICE-Lite / DTLS answer.
// The cryptographic half — real ICE, DTLS and SRTP — is exercised
// end-to-end in media.TestWebRTCSessionEndToEnd.
func TestCaseD_WebRTCCallSDP(t *testing.T) {
	h := startHarness(t, true)
	browser := newWSClient(t)

	invite := browser.buildInvite("1001", "2002", "example.com", browserOfferSDP(51234))
	res := browser.do(t, invite, h.publicWS)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200\n%s", res.StatusCode, res.String())
	}

	// --- FreeSWITCH must see ordinary RTP, with nothing WebRTC in it ---
	invites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invites) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs", len(invites))
	}
	body := string(invites[0].Body())
	for _, forbidden := range []string{
		"ice-ufrag", "ice-pwd", "candidate", "fingerprint", "setup:",
		"rtcp-mux", "SAVPF", "UDP/TLS", "192.168.44.44", "203.0.113.99",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("upstream offer leaks %q:\n%s", forbidden, body)
		}
	}
	upstream, err := parseLabSDP(invites[0].Body())
	if err != nil {
		t.Fatalf("upstream offer unparseable: %v", err)
	}
	if upstream.Audio.WebRTC() {
		t.Error("upstream offer is not plain RTP")
	}
	// Opus and its parameters must survive: no transcoding means the
	// payload number and fmtp reach FreeSWITCH exactly as offered.
	if !strings.Contains(body, "a=rtpmap:111 opus/48000/2") {
		t.Errorf("opus lost upstream:\n%s", body)
	}
	if !strings.Contains(body, "a=fmtp:111 minptime=10;useinbandfec=1") {
		t.Errorf("opus fmtp lost upstream:\n%s", body)
	}

	// --- the browser must see a complete ICE-Lite / DTLS answer ---
	ans := string(res.Body())
	for _, want := range []string{
		"UDP/TLS/RTP/SAVPF", "a=ice-lite", "a=ice-ufrag:", "a=ice-pwd:",
		"a=candidate:", "typ host", "a=fingerprint:sha-256 ", "a=setup:passive",
		"a=rtcp-mux",
	} {
		if !strings.Contains(ans, want) {
			t.Errorf("browser answer missing %q:\n%s", want, ans)
		}
	}
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatalf("answer unparseable: %v", err)
	}
	if !answer.Audio.WebRTC() {
		t.Error("answer is not a valid WebRTC body")
	}
	// The answer's fingerprint must be the SBC's real DTLS identity, not
	// an echo of the browser's.
	if answer.Audio.Fingerprint == nil ||
		answer.Audio.Fingerprint.Value != h.srv.identity.FingerprintValue {
		t.Errorf("answer fingerprint is not the SBC's own: %v", answer.Audio.Fingerprint)
	}
	if strings.Contains(ans, "6B:8B:F0:65") {
		t.Error("answer echoes the browser's own fingerprint")
	}
	// The browser must never be told FreeSWITCH's media port.
	if answer.Audio.Port == h.fs.rtpPort {
		t.Error("the browser was given FreeSWITCH's RTP port")
	}

	// --- the anchored session is a WebRTC one ---
	d, ok := h.srv.dialogs.confirmed(fsip.CallID(invite))
	if !ok {
		t.Fatal("no call recorded")
	}
	if !d.session().IsWebRTC() {
		t.Error("media session is not a WebRTC session")
	}
	if snap := h.srv.metrics.Snapshot(); snap.ActiveWebRTCSessions != 1 {
		t.Errorf("active webrtc sessions = %d, want 1", snap.ActiveWebRTCSessions)
	}

	sendAck(t, browser, invite, res, h.publicWS)
	if r := browser.do(t, buildBye(browser, invite, res), h.publicWS); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// TestInboundCallReachesRegisteredClient is acceptance criterion 3: an
// INVITE from FreeSWITCH, addressed to the contact FreeSBC registered on a
// phone's behalf, reaches that phone.
func TestInboundCallReachesRegisteredClient(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()

	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	stored := h.fs.contacts()
	if len(stored) == 0 {
		t.Fatal("nothing registered")
	}

	// The phone answers with its own SDP.
	phoneRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer phoneRTP.Close()
	phonePort := phoneRTP.LocalAddr().(*net.UDPAddr).Port
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(phonePort)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		to := res.To()
		to.Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
	})

	// FreeSWITCH calls the stored contact — Request-URI and all.
	var ruri sip.Uri
	if err := sip.ParseUri(stored[0], &ruri); err != nil {
		t.Fatalf("stored contact %q unparseable: %v", stored[0], err)
	}

	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("inbound INVITE: got %d, want 200", res.StatusCode)
	}

	select {
	case got := <-phone.inbound:
		if got.Method != sip.INVITE {
			t.Fatalf("phone received %s, want INVITE", got.Method)
		}
		// The phone must be addressed as itself, not as the SBC's contact.
		if got.Recipient.User != "1001" {
			t.Errorf("Request-URI user = %q, want 1001", got.Recipient.User)
		}
		if strings.Contains(got.Recipient.String(), contactTokenParam+"=") {
			t.Errorf("binding token leaked to the phone: %s", got.Recipient.String())
		}
		// And it must be offered the SBC's media, not FreeSWITCH's.
		offer, err := parseLabSDP(got.Body())
		if err != nil {
			t.Fatalf("inbound offer unparseable: %v", err)
		}
		if offer.Audio.Port == h.fs.rtpPort {
			t.Error("the phone was offered FreeSWITCH's own RTP port")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the phone never received the INVITE")
	}

	// The answer FreeSWITCH got must point at the SBC's private media.
	upstreamAnswer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatalf("answer to FreeSWITCH unparseable: %v", err)
	}
	if upstreamAnswer.Audio.Port == phonePort {
		t.Error("FreeSWITCH was given the phone's own RTP port")
	}
}

// An INVITE to a contact nobody holds any more must be refused cleanly.
func TestInboundCallToUnknownContact(t *testing.T) {
	h := startHarness(t, false)
	ruri := sip.Uri{User: "9999", Host: "127.0.0.1", Port: portOf(h.privateSIP), UriParams: sip.NewParams()}
	ruri.UriParams.Add(contactTokenParam, "no-such-token")
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 404 {
		t.Errorf("got %d, want 404", res.StatusCode)
	}
	waitForRelease(t, h)
}

// A call whose codecs do not intersect must be rejected, never transcoded.
func TestCallWithNoCommonCodecRejected(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	// FreeSWITCH answers with a codec the phone never offered.
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		body := "v=0\r\no=FreeSWITCH 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
			"m=audio 9998 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n"
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = tx.Respond(res)
		return true
	})
	phoneRTP := 30001
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(phoneRTP)), h.publicUDP)
	if res.StatusCode != 488 {
		t.Errorf("got %d, want 488 Not Acceptable Here", res.StatusCode)
	}
	waitForRelease(t, h)
}

// A rejected call must release its media immediately, not wait for the
// silence watchdog.
func TestRejectedCallReleasesMedia(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
		return true
	})
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30003)), h.publicUDP)
	if res.StatusCode != 486 {
		t.Fatalf("got %d, want 486", res.StatusCode)
	}
	waitForRelease(t, h)
}

// OPTIONS is answered locally rather than multiplied onto FreeSWITCH.
func TestOptionsAnsweredLocally(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	req := sip.NewRequest(sip.OPTIONS, sip.Uri{Host: "example.com"})
	from := &sip.FromHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{Host: "example.com"}, Params: sip.NewParams()})
	callID := sip.CallIDHeader("opt-1")
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.OPTIONS})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)

	res := phone.do(t, req, h.publicUDP)
	if res.StatusCode != 200 {
		t.Errorf("OPTIONS: got %d", res.StatusCode)
	}
	if got := h.fs.received(sip.OPTIONS); len(got) != 0 {
		t.Errorf("OPTIONS was forwarded upstream %d times", len(got))
	}
}

// TestByeFromUpstreamReachesClient covers the hangup direction no other
// test drives: FreeSWITCH ends the call (callee hung up, voicemail
// finished, dialplan hangup) and the BYE must reach the client.
//
// The request FreeSWITCH sends carries no binding token — the token only
// ever rides on the REGISTERed contact, not on the dialog's remote target
// — so routing it depends on the dialog record, not the location table.
func TestByeFromUpstreamReachesClient(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	// Capture the To tag the switch generated, so the BYE can name the
	// dialog correctly. It travels over a channel rather than a shared
	// variable: the hook runs on a sipgo handler goroutine.
	tagCh := make(chan string, 1)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		tag := sip.GenerateTagN(12)
		res.To().Params.Add("tag", tag)
		_ = tx.Respond(res)
		tagCh <- tag
		return true
	})

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30201))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	sendAck(t, phone, invite, res, h.publicUDP)

	var switchTag string
	select {
	case switchTag = <-tagCh:
	case <-time.After(3 * time.Second):
		t.Fatal("the switch never answered")
	}
	upstreamInvites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(upstreamInvites) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs", len(upstreamInvites))
	}

	// Drain anything the phone already received so the BYE is unambiguous.
	drain(phone.inbound)

	byeRes := h.fs.inDialog(t, sip.BYE, upstreamInvites[0], switchTag)
	if byeRes.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d, want 200", byeRes.StatusCode)
	}

	select {
	case got := <-phone.inbound:
		if got.Method != sip.BYE {
			t.Fatalf("the phone received %s, want BYE", got.Method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the phone never received the BYE — the call would hang until the media watchdog fired")
	}
	waitForRelease(t, h)
}

// TestByeForwardFailureAnswers200 guards what FreeSBC answers when a BYE
// genuinely cannot be forwarded — the far side is gone, the write fails
// before it leaves the socket. The dialog is over either way, so the
// switch must not be told its hangup failed: answering 408 makes sofia
// treat the BYE as failed and keep the leg. The proxy answers 200, makes
// one best-effort stateless attempt to put the BYE on the wire itself,
// and tears the media down.
//
// The failure is forced deterministically: once the call is up, the
// dialog's recorded public remote — the address every request toward the
// phone is sent to — is replaced with one the socket cannot send to, so
// the BYE fails before a byte leaves. Any transport-level failure on the
// public plane produces the same situation the wildcard-bind bug produced
// in production; this is the one that needs no second socket and no
// mutable topology.
func TestByeForwardFailureAnswers200(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	tagCh := make(chan string, 1)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		tag := sip.GenerateTagN(12)
		res.To().Params.Add("tag", tag)
		_ = tx.Respond(res)
		tagCh <- tag
		return true
	})

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30601))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	sendAck(t, phone, invite, res, h.publicUDP)
	var switchTag string
	select {
	case switchTag = <-tagCh:
	case <-time.After(3 * time.Second):
		t.Fatal("the switch never answered")
	}
	upstreamInvites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(upstreamInvites) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs", len(upstreamInvites))
	}
	drain(phone.inbound)

	// Sabotage the dialog's recorded public remote. It is what
	// directionFor hands the forwarder as the BYE's destination, and an
	// address with no port is one the transport layer cannot send to at
	// all: the forward fails before a byte leaves, which is the situation
	// this test is about — a hangup the proxy cannot deliver. The dialog
	// table's own mutex is what makes the write safe while the proxy is
	// serving.
	d := waitForDialog(t, h, fsip.CallID(invite))
	h.srv.dialogs.mu.Lock()
	d.route.publicRemote = "127.0.0.1"
	h.srv.dialogs.mu.Unlock()

	// The BYE cannot go out, yet FreeSWITCH must be answered 200 — a 408
	// here tells it the hangup failed — and the media must be released.
	// (The call itself set up fine: nothing needs an outbound public-plane
	// connection until FreeSWITCH sends a request of its own.)
	byeRes := h.fs.inDialog(t, sip.BYE, upstreamInvites[0], switchTag)
	if byeRes.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d %s, want 200 — a failed hangup must not be "+
			"answered 408, or the switch keeps the leg", byeRes.StatusCode, byeRes.Reason)
	}
	waitForRelease(t, h)
}

func drain(ch chan *sip.Request) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// TestReInviteKeepsMediaAnchored is acceptance criteria 9 and 10 for the
// in-dialog case: a re-INVITE (sip.js hold/unhold, a FreeSWITCH session
// timer refresh) must not hand either side the other's media address.
//
// Passing the body through untouched would point FreeSWITCH straight at
// the client and vice versa — media would leave the SBC entirely, mid-call.
func TestReInviteKeepsMediaAnchored(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30301))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	sendAck(t, phone, invite, res, h.publicUDP)

	firstAnswer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}
	anchoredPublicPort := firstAnswer.Audio.Port

	// The client re-INVITEs to put the call on hold, from a DIFFERENT
	// media port — a real endpoint may re-offer with new parameters.
	reOffer := strings.Replace(phoneOfferSDP(30302), "a=sendrecv", "a=sendonly", 1)
	re := sip.NewRequest(sip.INVITE, invite.Recipient)
	sip.CopyHeaders("From", invite, re)
	sip.CopyHeaders("Call-ID", invite, re)
	re.AppendHeader(sip.HeaderClone(res.To()))
	re.AppendHeader(&sip.CSeqHeader{SeqNo: invite.CSeq().SeqNo + 1, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	re.AppendHeader(&mf)
	re.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
	re.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	via.Params.Add("rport", "")
	re.PrependHeader(via)
	copyRouteFromRecordRoute(res, re)
	re.SetBody([]byte(reOffer))

	reRes := phone.do(t, re, h.publicUDP)
	if reRes.StatusCode != 200 {
		t.Fatalf("re-INVITE: got %d, want 200", reRes.StatusCode)
	}

	// --- what FreeSWITCH was re-offered ---
	invites := h.fs.waitFor(sip.INVITE, 2, 3*time.Second)
	if len(invites) < 2 {
		t.Fatalf("FreeSWITCH saw %d INVITEs, want 2", len(invites))
	}
	upstream, err := parseLabSDP(invites[1].Body())
	if err != nil {
		t.Fatalf("re-offer to FreeSWITCH unparseable: %v\n%s", err, invites[1].Body())
	}
	if upstream.Audio.Port == 30302 {
		t.Error("the re-INVITE handed FreeSWITCH the client's own media port — media would bypass the SBC")
	}
	privRange := h.store.Current().RTP.Private
	if upstream.Audio.Port < privRange.PortMin || upstream.Audio.Port > privRange.PortMax {
		t.Errorf("re-offer media port %d is outside the private pool", upstream.Audio.Port)
	}
	// The direction must survive: it is what puts the call on hold.
	if upstream.Audio.Direction != sdp.SendOnly {
		t.Errorf("hold direction lost: %v", upstream.Audio.Direction)
	}

	// --- what the client was answered ---
	reAnswer, err := parseLabSDP(reRes.Body())
	if err != nil {
		t.Fatalf("re-answer unparseable: %v\n%s", err, reRes.Body())
	}
	if reAnswer.Audio.Port == h.fs.rtpPort {
		t.Error("the re-INVITE answer handed the client FreeSWITCH's media port")
	}
	// Media stays on the ports it already holds: the anchor does not move.
	if reAnswer.Audio.Port != anchoredPublicPort {
		t.Errorf("public media port moved on re-INVITE: %d → %d", anchoredPublicPort, reAnswer.Audio.Port)
	}

	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// TestSingleViaProvisionalIsAbsorbed guards the behaviour a live
// FreeSWITCH exposed: sofia sends its 100 Trying with ONLY the topmost Via
// (its peer's — ours), not the full stack. A proxy that pops the top Via
// unconditionally leaves that response with no Via at all, and the
// requester's transaction layer cannot match it.
//
// RFC 3261 §16.7 settles both halves: step 2 says a 100 Trying is
// hop-by-hop and MUST NOT be forwarded, and step 3 says the top Via must
// be checked against the proxy's own before it is removed.
func TestSingleViaProvisionalIsAbsorbed(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		// A 100 Trying carrying only the top Via, as sofia sends it.
		trying := sip.NewResponseFromRequest(req, 100, "Trying", nil)
		for len(trying.GetHeaders("Via")) > 1 {
			// Keep only the first.
			vias := trying.GetHeaders("Via")
			trying.RemoveHeader("Via")
			first := vias[0]
			trying.RemoveHeader("Via")
			trying.PrependHeader(sip.HeaderClone(first))
			break
		}
		_ = tx.Respond(trying)

		// A 180 with the same defect: it must not reach the caller
		// malformed, and must not prevent the call from completing.
		ringing := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
		ringing.RemoveHeader("Via")
		_ = tx.Respond(ringing)

		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		_ = tx.Respond(res)
		return true
	})

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30401))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("a defective provisional broke the call: got %d, want 200", res.StatusCode)
	}
	sendAck(t, phone, invite, res, h.publicUDP)
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// waitForDialog waits for the record a 2xx commits. Both INVITE paths
// relay the final response BEFORE they commit the dialog, so a test that
// reaches for the record immediately would race the commit.
func waitForDialog(t *testing.T, h *harness, callID string) *dialog {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if d, ok := h.srv.dialogs.confirmed(callID); ok {
			return d
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("dialog %s was never committed", callID)
	return nil
}
