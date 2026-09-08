package proxy

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/sdp"
)

// This file exercises the peer-to-peer PSTN trunk: FreeSWITCH bridges an
// outbound call to sip.pstn.match (the proxy's public UDP port, reached
// over the private link), the proxy classifies it — source is the
// upstream AND the Request-URI names the match — and forwards it to the
// carrier gateway with media anchored exactly like an inbound call to a
// registered client. The gateway is a peer: it never registers and FreeSBC
// never pings it.

// placePSTNCall drives one FreeSWITCH-bridged call to the carrier through
// the full happy path at the signaling layer: the fake switch INVITEs the
// match address on the public socket, the carrier answers 200 with its own
// SDP and a fresh To tag, and the switch ACKs once the proxy has committed
// the call. It returns the INVITE the carrier saw, the final response
// FreeSWITCH got, and the carrier's To tag.
func placePSTNCall(t *testing.T, h *harness, carrier *fakeSwitch, number string) (*sip.Request, *sip.Response, string) {
	t.Helper()

	// The carrier answers with its own tag (a real gateway's 200 carries
	// one, and the dialog's later requests name it). The hook runs on a
	// sipgo handler goroutine, so the tag travels over a channel.
	tagCh := make(chan string, 1)
	carrier.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(carrier.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(carrier.addr)}})
		tag := sip.GenerateTagN(12)
		res.To().Params.Add("tag", tag)
		_ = tx.Respond(res)
		tagCh <- tag
		return true
	})

	// The dialplan bridge: an INVITE whose Request-URI is the called number
	// AT the match address, sent to that same address — the proxy's public
	// socket — from the upstream's own source.
	ruri := sip.Uri{User: number, Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	res := h.fs.call(t, ruri, h.publicUDP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("bridged INVITE: got %d, want 200", res.StatusCode)
	}

	var tag string
	select {
	case tag = <-tagCh:
	case <-time.After(3 * time.Second):
		t.Fatal("the carrier never answered")
	}
	invites := carrier.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invites) != 1 {
		t.Fatalf("the carrier saw %d INVITEs, want 1", len(invites))
	}

	// The 2xx ACK must not race the proxy's call commit: until the call is
	// on record, an ACK arriving at the private socket has no dialog to
	// route by and would be dropped, and a UAC never retransmits a 2xx ACK.
	waitForCommitted(t, h)
	h.fs.sendAckTo2xx(t, res)
	return invites[0], res, tag
}

// waitForCommitted waits until the proxy holds exactly one call — the one
// the test just placed. See placePSTNCall for why the ACK must follow it.
func waitForCommitted(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.ActiveCalls() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the call was never committed")
}

// TestPSTNOutboundCallHappyPath is the whole feature end to end: the
// bridged call reaches the carrier addressed as the called number, the
// media is anchored on both legs (each side offered the SBC's own port on
// its own plane, never the other side's), audio relays in both directions,
// and the carrier's hangup reaches FreeSWITCH.
func TestPSTNOutboundCallHappyPath(t *testing.T) {
	h, carrier := startHarnessPSTN(t)

	// The endpoints' media sockets, on the ports their SDP advertises.
	carrierRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: carrier.rtpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer carrierRTP.Close()
	fsRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: h.fs.rtpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer fsRTP.Close()

	carrierInvite, resAtFS, carrierTag := placePSTNCall(t, h, carrier, "12345")

	// --- what the carrier was offered ---
	// The called number survives in the Request-URI, but the host:port is
	// the gateway's own — FreeSWITCH dialed the match address, which must
	// not leak to the carrier as anything to call back.
	if carrierInvite.Recipient.User != "12345" {
		t.Errorf("carrier Request-URI user = %q, want the called number 12345", carrierInvite.Recipient.User)
	}
	if got := fmt.Sprintf("%s:%d", carrierInvite.Recipient.Host, carrierInvite.Recipient.Port); got != carrier.addr {
		t.Errorf("carrier Request-URI = %s, want the gateway %s", got, carrier.addr)
	}
	offer, err := sdp.Parse(carrierInvite.Body())
	if err != nil {
		t.Fatalf("carrier offer unparseable: %v\n%s", err, carrierInvite.Body())
	}
	// The carrier must never be pointed at FreeSWITCH's media: it is
	// offered a port from the public pool, the SBC's own.
	if offer.Audio.Port == h.fs.rtpPort {
		t.Error("the carrier was offered FreeSWITCH's own RTP port")
	}
	if pubRange := h.store.Current().RTP.Public; offer.Audio.Port < pubRange.PortMin || offer.Audio.Port > pubRange.PortMax {
		t.Errorf("carrier-facing media port %d is outside the public pool %d-%d",
			offer.Audio.Port, pubRange.PortMin, pubRange.PortMax)
	}
	// The Contact the carrier sees must be the SBC's public identity, or
	// its in-dialog requests would bypass the SBC entirely.
	if c, ok := contactURI(carrierInvite); !ok || c.Host != "127.0.0.1" || c.Port != portOf(h.publicUDP) {
		t.Errorf("carrier-facing Contact = %v, want the SBC's public identity 127.0.0.1:%d",
			c, portOf(h.publicUDP))
	}

	// --- what FreeSWITCH was answered ---
	answer, err := sdp.Parse(resAtFS.Body())
	if err != nil {
		t.Fatalf("answer to FreeSWITCH unparseable: %v\n%s", err, resAtFS.Body())
	}
	if answer.Audio.Port == carrier.rtpPort {
		t.Error("FreeSWITCH was given the carrier's own RTP port")
	}
	if privRange := h.store.Current().RTP.Private; answer.Audio.Port < privRange.PortMin || answer.Audio.Port > privRange.PortMax {
		t.Errorf("FreeSWITCH-facing media port %d is outside the private pool %d-%d",
			answer.Audio.Port, privRange.PortMin, privRange.PortMax)
	}
	if c, ok := contactURI(resAtFS); !ok || c.Host != "127.0.0.1" || c.Port != portOf(h.privateSIP) {
		t.Errorf("FreeSWITCH-facing Contact = %v, want the SBC's private identity 127.0.0.1:%d",
			c, portOf(h.privateSIP))
	}

	// The switch's ACK must have reached the carrier.
	if acks := carrier.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Errorf("the carrier saw %d ACKs, want 1", len(acks))
	}

	// --- bidirectional media through the SBC ---
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: offer.Audio.Port}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answer.Audio.Port}
	audio := rtpPacket(0, 300, 160)
	if !relayReaches(t, carrierRTP, sbcPublic, fsRTP, audio) {
		t.Fatal("carrier → FreeSWITCH audio never arrived")
	}
	back := rtpPacket(0, 400, 160)
	if !relayReaches(t, fsRTP, sbcPrivate, carrierRTP, back) {
		t.Fatal("FreeSWITCH → carrier audio never arrived")
	}

	// --- the carrier hangs up first; the BYE must reach FreeSWITCH ---
	byeRes := carrier.inDialog(t, sip.BYE, carrierInvite, carrierTag)
	if byeRes.StatusCode != 200 {
		t.Fatalf("BYE from the carrier: got %d, want 200", byeRes.StatusCode)
	}
	if byes := h.fs.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
		t.Errorf("FreeSWITCH saw %d BYEs, want 1", len(byes))
	}
	waitForRelease(t, h)
}

// TestPSTNFSHangupReachesCarrier is the other hangup direction: FreeSWITCH
// (or its dialplan) ends the bridged call, and the BYE must reach the
// carrier through the call record — it carries no binding token, so the
// dialog record is the only thing that can route it.
func TestPSTNFSHangupReachesCarrier(t *testing.T) {
	h, carrier := startHarnessPSTN(t)
	_, resAtFS, _ := placePSTNCall(t, h, carrier, "9876543")

	// The call is live on the proxy before anything hangs up.
	if h.srv.ActiveCalls() != 1 {
		t.Fatalf("active calls = %d, want 1", h.srv.ActiveCalls())
	}

	byeRes := h.fs.uacBye(t, resAtFS)
	if byeRes.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d, want 200", byeRes.StatusCode)
	}
	if byes := carrier.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
		t.Errorf("the carrier saw %d BYEs, want 1", len(byes))
	}
	waitForRelease(t, h)
}

// TestPSTNNoMatchInviteStill404s guards the classification's R-URI half: a
// call from the upstream that does NOT name the match is ordinary
// FreeSWITCH→client traffic and keeps its pre-feature behaviour (404 for an
// unknown contact) — the carrier must never see it.
func TestPSTNNoMatchInviteStill404s(t *testing.T) {
	h, carrier := startHarnessPSTN(t)

	ruri := sip.Uri{User: "9999", Host: "127.0.0.1", Port: portOf(h.privateSIP), UriParams: sip.NewParams()}
	ruri.UriParams.Add(contactTokenParam, "no-such-token")
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 404 {
		t.Errorf("got %d, want 404", res.StatusCode)
	}
	if got := carrier.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the carrier saw %d INVITEs for non-PSTN traffic", len(got))
	}
	waitForRelease(t, h)
}

// TestPSTNUnconfiguredFallsBackTo404 is the back-compat guard: WITHOUT
// sip.pstn configured, a bridged-shaped call — the called number at the
// public UDP address, sent by FreeSWITCH over the private link — is
// handled exactly as before the feature existed. Nothing registers it, so
// it is refused 404 like any other unknown contact, and nothing is
// forwarded upstream.
func TestPSTNUnconfiguredFallsBackTo404(t *testing.T) {
	h := startHarness(t, false)

	ruri := sip.Uri{User: "12345", Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 404 {
		t.Errorf("got %d, want 404", res.StatusCode)
	}
	if got := h.fs.received(sip.INVITE); len(got) != 0 {
		t.Errorf("FreeSWITCH received %d of its own INVITEs back", len(got))
	}
	waitForRelease(t, h)
}

// TestPSTNMatchFromNonUpstreamFallsThrough guards the classification's
// source half: a phone on the public side dialing an address that happens
// to equal the match must NOT be whisked off to the carrier — the request
// did not come from the upstream. It is proxied upstream like any other
// client call. This is why the PSTN harness keeps the upstream on its own
// loopback address (see startHarnessPSTN).
func TestPSTNMatchFromNonUpstreamFallsThrough(t *testing.T) {
	h, carrier := startHarnessPSTN(t)
	phone := newUDPClient(t)

	invite := phone.buildInvite("1001", "12345", "127.0.0.1", phoneOfferSDP(30001))
	// Dial the match address itself: the R-URI would satisfy the match
	// check if the request had come from the upstream.
	invite.Recipient = sip.Uri{User: "12345", Host: "127.0.0.1", Port: portOf(h.publicUDP)}

	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	if got := carrier.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the carrier saw %d INVITEs from a phone call", len(got))
	}
	invites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invites) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs, want 1", len(invites))
	}

	// A client's 2xx ACK is never retransmitted, so it must not race the
	// proxy's commit of the call record — without it the ACK cannot be
	// routed to FreeSWITCH.
	waitForCommitted(t, h)
	sendAck(t, phone, invite, res, h.publicUDP)
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Errorf("FreeSWITCH saw %d ACKs, want 1", len(acks))
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// TestPSTNNoCommonCodecRejected mirrors the client-call codec test: the
// carrier answers with a codec FreeSWITCH never offered, so the media
// cannot be anchored. FreeSWITCH must get 488 — and the carrier, which
// believes it has a live dialog after its 2xx, must be ACKed and then
// BYEd, or it would sit retransmitting the 200.
func TestPSTNNoCommonCodecRejected(t *testing.T) {
	h, carrier := startHarnessPSTN(t)

	carrier.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		body := "v=0\r\no=gw 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
			"m=audio 9998 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n"
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = tx.Respond(res)
		return true
	})

	ruri := sip.Uri{User: "12345", Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	res := h.fs.call(t, ruri, h.publicUDP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 488 {
		t.Errorf("got %d, want 488 Not Acceptable Here", res.StatusCode)
	}
	// The unanchorable 2xx was completed and torn down toward the carrier.
	if acks := carrier.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Errorf("the carrier saw %d ACKs, want 1", len(acks))
	}
	if byes := carrier.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
		t.Errorf("the carrier saw %d BYEs, want 1", len(byes))
	}
	waitForRelease(t, h)
}
