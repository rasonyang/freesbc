package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
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

// ---------------------------------------------------------------------
// The multi-gateway trunk (sip.pstn.gateways + sip.pstn.routes): a number
// is routed by prefix onto a list of gateways, tried in order until one
// connects the call. The single-gateway v1 shape above is an alias of this
// one (one gateway, one catch-all route — see buildTopology), so these
// tests exercise the same runtime machinery the v1 tests exercise.
// ---------------------------------------------------------------------

// bridgePSTNCall is placePSTNCall without its happy-path assertions: one
// dialplan bridge to the trunk. When a gateway answers, the call is
// committed and ACKed; the final response — whatever it is — comes back to
// the caller, who decides what the code proves.
func bridgePSTNCall(t *testing.T, h *harness, number string) *sip.Response {
	t.Helper()
	ruri := sip.Uri{User: number, Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	res := h.fs.call(t, ruri, h.publicUDP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode == 200 {
		waitForCommitted(t, h)
		h.fs.sendAckTo2xx(t, res)
	}
	return res
}

// hangupPSTN ends a committed bridged call from the FreeSWITCH side and
// waits for the media and the call record to drain.
func hangupPSTN(t *testing.T, h *harness, res *sip.Response) {
	t.Helper()
	if byeRes := h.fs.uacBye(t, res); byeRes.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d, want 200", byeRes.StatusCode)
	}
	waitForRelease(t, h)
}

// branchOf returns the top Via branch of a request — what RFC 3261 §9.1
// matches a CANCEL to its INVITE by.
func branchOf(m sip.Message) string {
	v := m.Via()
	if v == nil {
		return ""
	}
	b, _ := v.Params.Get("branch")
	return b
}

// callAsync is call() without the wait: it places FreeSWITCH's bridged
// INVITE and returns immediately — the request object, and the channel its
// final response will arrive on (nil if the transaction never finalises).
// Tests that must act while the trunk is still ringing — feeding a gateway
// early media, or giving up mid-ring — use it instead of call().
//
// The transaction sends a CLONE: sipgo mutates the request it is sending,
// so the caller's copy is a pristine snapshot that later requests (a
// CANCEL built from it) can read without racing the send.
func (f *fakeSwitch) callAsync(t *testing.T, ruri sip.Uri, dest, body string) (*sip.Request, chan *sip.Response) {
	t.Helper()
	req := sip.NewRequest(sip.INVITE, ruri)
	from := &sip.FromHeader{Address: sip.Uri{User: "3003", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: ruri, Params: sip.NewParams()})
	callID := sip.CallIDHeader(fmt.Sprintf("fs-call-%d", time.Now().UnixNano()))
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: "127.0.0.1", Port: portOf(f.addr)}})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "127.0.0.1", Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	req.SetBody([]byte(body))
	req.SetTransport("UDP")
	req.SetDestination(dest)
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}

	txReq := req.Clone()
	final := make(chan *sip.Response, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := f.cli.TransactionRequest(ctx, txReq)
		if err != nil {
			final <- nil
			return
		}
		defer tx.Terminate()
		for {
			select {
			case res, ok := <-tx.Responses():
				if !ok {
					final <- nil
					return
				}
				if res.StatusCode >= 200 {
					final <- res
					return
				}
			case <-tx.Done():
				final <- nil
				return
			case <-ctx.Done():
				final <- nil
				return
			}
		}
	}()
	return req, final
}

// cancelCall sends the CANCEL for a callAsync INVITE, the way FreeSWITCH's
// dialplan gives up on a ringing bridge: RFC 3261 §9.1 — same Request-URI,
// top Via branch, Call-ID, From and To, CSeq — toward the same destination,
// from the switch's own socket. The response is absorbed; the CANCEL is a
// separate transaction the switch does not wait on here.
func (f *fakeSwitch) cancelCall(t *testing.T, invite *sip.Request, dest string) {
	t.Helper()
	cn := sip.NewRequest(sip.CANCEL, invite.Recipient)
	cn.AppendHeader(sip.HeaderClone(invite.Via()))
	sip.CopyHeaders("From", invite, cn)
	sip.CopyHeaders("To", invite, cn)
	sip.CopyHeaders("Call-ID", invite, cn)
	cn.AppendHeader(&sip.CSeqHeader{SeqNo: invite.CSeq().SeqNo, MethodName: sip.CANCEL})
	mf := sip.MaxForwardsHeader(70)
	cn.AppendHeader(&mf)
	cn.SetTransport("UDP")
	cn.SetDestination(dest)
	cn.Laddr = invite.Laddr
	if err := f.cli.WriteRequest(cn); err != nil {
		t.Fatalf("fake switch CANCEL: %v", err)
	}
}

// A prefix route steers each number to the gateway that owns its range, and
// numbers no prefix owns fall to the catch-all: the route table, not the
// dialed number, chooses the carrier.
func TestPSTNRoutePicksGatewayByNumberPrefix(t *testing.T) {
	const (
		mobile = "gw-mobile"
		fixed  = "gw-fixed"
	)
	routes := "      - match: '^13\\d{9}$'\n        to: [" + mobile + "]\n      - to: [" + fixed + "]\n"
	h, gws := startHarnessPSTNGateways(t, "", routes, map[string]string{
		mobile: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		fixed:  fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwMobile, gwFixed := gws[mobile], gws[fixed]
	gwMobile.setInviteHook(gwMobile.answerHook(200, true))
	gwFixed.setInviteHook(gwFixed.answerHook(200, true))

	// A 13-prefixed mobile number lands on the mobile gateway, addressed as
	// the called number AT the gateway itself — and nothing is dialed
	// anywhere else.
	res := bridgePSTNCall(t, h, "13800138000")
	if res.StatusCode != 200 {
		t.Fatalf("mobile call: got %d, want 200", res.StatusCode)
	}
	inv := gwMobile.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(inv) != 1 {
		t.Fatalf("gw-mobile saw %d INVITEs, want 1", len(inv))
	}
	if inv[0].Recipient.User != "13800138000" {
		t.Errorf("gw-mobile Request-URI user = %q, want the called number", inv[0].Recipient.User)
	}
	if got := fmt.Sprintf("%s:%d", inv[0].Recipient.Host, inv[0].Recipient.Port); got != gwMobile.addr {
		t.Errorf("gw-mobile Request-URI = %s, want the gateway %s", got, gwMobile.addr)
	}
	if got := gwFixed.received(sip.INVITE); len(got) != 0 {
		t.Errorf("gw-fixed saw %d INVITEs for a mobile number", len(got))
	}
	hangupPSTN(t, h, res)

	// Any other number falls through the prefix route to the catch-all.
	res = bridgePSTNCall(t, h, "88001234")
	if res.StatusCode != 200 {
		t.Fatalf("fixed-line call: got %d, want 200", res.StatusCode)
	}
	inv = gwFixed.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(inv) != 1 {
		t.Fatalf("gw-fixed saw %d INVITEs, want 1", len(inv))
	}
	if inv[0].Recipient.User != "88001234" {
		t.Errorf("gw-fixed Request-URI user = %q, want the called number", inv[0].Recipient.User)
	}
	if got := fmt.Sprintf("%s:%d", inv[0].Recipient.Host, inv[0].Recipient.Port); got != gwFixed.addr {
		t.Errorf("gw-fixed Request-URI = %s, want the gateway %s", got, gwFixed.addr)
	}
	if got := gwMobile.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-mobile saw %d INVITEs, want still 1", len(got))
	}
	hangupPSTN(t, h, res)
}

// A rejecting gateway is skipped, not fatal: the first gateway's 503 is
// HELD — FreeSWITCH never sees it — and the series dials the second, whose
// 200 is relayed and committed. The dialog then rides the WINNER: the
// switch's ACK and BYE both reach gw-b, never the failed gw-a.
func TestPSTNFailoverAfterGatewayFailure(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwA, gwB := gws["gw-a"], gws["gw-b"]
	gwA.setInviteHook(gwA.answerHook(503, false))
	gwB.setInviteHook(gwB.answerHook(200, true))

	res := bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 200 {
		t.Fatalf("bridged call: got %d, want 200 (the held 503 must never surface)", res.StatusCode)
	}
	if got := gwA.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-a saw %d INVITEs, want 1", len(got))
	}
	if got := gwB.waitFor(sip.INVITE, 1, 3*time.Second); len(got) != 1 {
		t.Errorf("gw-b saw %d INVITEs, want 1", len(got))
	}
	if acks := gwB.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Errorf("gw-b saw %d ACKs, want 1", len(acks))
	}
	if got := gwA.received(sip.ACK); len(got) != 0 {
		t.Errorf("gw-a saw %d ACKs, want 0", len(got))
	}
	hangupPSTN(t, h, res)
	if byes := gwB.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
		t.Errorf("gw-b saw %d BYEs, want 1", len(byes))
	}
}

// A gateway that swallows the INVITE (no provisional, no final) is given
// attempt_timeout, then cancelled — the CANCEL echoes the INVITE's own Via
// branch, RFC 3261 §9.1 — and the series dials the next gateway carrying
// the SAME dialog: FreeSWITCH's Call-ID and CSeq ride both attempts, while
// each attempt has a Via branch of its own.
func TestPSTNSilentGatewayTimesOutAndFailsOver(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "300ms", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwA, gwB := gws["gw-a"], gws["gw-b"]
	gwA.setInviteHook(gwA.silentHook())
	gwB.setInviteHook(gwB.answerHook(200, true))

	res := bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 200 {
		t.Fatalf("bridged call: got %d, want 200", res.StatusCode)
	}
	invA := gwA.waitFor(sip.INVITE, 1, 3*time.Second)
	invB := gwB.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invA) != 1 || len(invB) != 1 {
		t.Fatalf("gateways saw %d/%d INVITEs, want 1 each", len(invA), len(invB))
	}
	if a, b := callIDOf(invA[0]), callIDOf(invB[0]); a != b {
		t.Errorf("Call-ID changed across the failover: %q → %q", a, b)
	}
	if a, b := invA[0].CSeq().SeqNo, invB[0].CSeq().SeqNo; a != b {
		t.Errorf("CSeq changed across the failover: %d → %d", a, b)
	}
	if branchOf(invA[0]) == branchOf(invB[0]) {
		t.Error("both attempts carried the same Via branch")
	}
	// gw-a must have been cancelled, by a CANCEL echoing its INVITE branch.
	if cans := gwA.waitFor(sip.CANCEL, 1, 3*time.Second); len(cans) != 1 {
		t.Fatalf("gw-a saw %d CANCELs, want 1", len(cans))
	} else if branchOf(cans[0]) != branchOf(invA[0]) {
		t.Errorf("CANCEL branch %q does not echo the INVITE's %q", branchOf(cans[0]), branchOf(invA[0]))
	}
	// The failover INVITE is re-pointed at the winning gateway.
	if got := fmt.Sprintf("%s:%d", invB[0].Recipient.Host, invB[0].Recipient.Port); got != gwB.addr {
		t.Errorf("gw-b Request-URI = %s, want the gateway %s", got, gwB.addr)
	}
	hangupPSTN(t, h, res)
}

// A number no route matches is refused 503 before any gateway is dialed: it
// is not this trunk's call, and FreeSWITCH's bridge is expected to fail
// over around it.
func TestPSTNUnroutedNumberRefusedBeforeDialing(t *testing.T) {
	// Only a 13-prefixed route; a plain number has nowhere to go. gw-b
	// exists to prove the series never dials anything for an unrouted
	// number — not even its first choice.
	routes := "      - match: '^13\\d{9}$'\n        to: [gw-a]\n"
	h, gws := startHarnessPSTNGateways(t, "", routes, map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})

	res := bridgePSTNCall(t, h, "88001234")
	if res.StatusCode != 503 {
		t.Errorf("got %d, want 503 Service Unavailable", res.StatusCode)
	}
	if got := gws["gw-a"].received(sip.INVITE); len(got) != 0 {
		t.Errorf("gw-a saw %d INVITEs for an unrouted number", len(got))
	}
	if got := gws["gw-b"].received(sip.INVITE); len(got) != 0 {
		t.Errorf("gw-b saw %d INVITEs for an unrouted number", len(got))
	}
	waitForRelease(t, h)
}

// When every gateway fails with a real final, FreeSWITCH hears the LAST
// one: the first attempt's 503 is held, the second's 500 is synthesised as
// the series' one verdict.
func TestPSTNExhaustionSynthesisesLastRealCode(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwA, gwB := gws["gw-a"], gws["gw-b"]
	gwA.setInviteHook(gwA.answerHook(503, false))
	gwB.setInviteHook(gwB.answerHook(500, false))

	res := bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 500 {
		t.Errorf("got %d, want the last real code 500", res.StatusCode)
	}
	if got := gwA.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-a saw %d INVITEs, want 1", len(got))
	}
	if got := gwB.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-b saw %d INVITEs, want 1", len(got))
	}
	waitForRelease(t, h)
}

// A 4xx other than 408 is the far end's verdict on THIS call — a busy
// number will be busy on every gateway — so it is relayed to FreeSWITCH
// as-is and the series stops: no CANCEL, no second gateway.
func TestPSTNRelayedFinalStopsTheSeries(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwA, gwB := gws["gw-a"], gws["gw-b"]
	gwA.setInviteHook(gwA.answerHook(486, false))

	res := bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 486 {
		t.Errorf("got %d, want 486 Busy Here", res.StatusCode)
	}
	if got := gwA.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-a saw %d INVITEs, want 1", len(got))
	}
	if got := gwB.received(sip.INVITE); len(got) != 0 {
		t.Errorf("gw-b saw %d INVITEs, want 0 — the series must stop at a relayed final", len(got))
	}
	if got := gwA.received(sip.CANCEL); len(got) != 0 {
		t.Errorf("gw-a saw %d CANCELs, want 0 — it answered the call", len(got))
	}
	waitForRelease(t, h)
}

// Cooldown, observed from the outside: a gateway whose whole attempt
// produced nothing is penalised, and the NEXT call skips it in favour of
// its healthy alternative (skip-if-alternatives) — but when every gateway
// is cooling the trunk dials the route's order anyway, because a cooldown
// is a suspicion, not a verdict (all-cooled-dial-anyway).
func TestPSTNCooldownSkipsSickGateway(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "300ms", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwA, gwB := gws["gw-a"], gws["gw-b"]
	gwA.setInviteHook(gwA.silentHook())
	gwB.setInviteHook(gwB.answerHook(200, true))

	// Call 1: gw-a rings into its 300ms budget, is cancelled, and earns
	// the 30s cooldown the expiry gives it; gw-b connects the call.
	res := bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 200 {
		t.Fatalf("call 1: got %d, want 200", res.StatusCode)
	}
	if cans := gwA.waitFor(sip.CANCEL, 1, 5*time.Second); len(cans) != 1 {
		t.Fatalf("gw-a saw %d CANCELs, want 1", len(cans))
	}
	hangupPSTN(t, h, res)

	// Call 2: gw-a is still cooling, so the route's first position goes to
	// gw-b and gw-a is not dialed at all.
	res = bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 200 {
		t.Fatalf("call 2: got %d, want 200", res.StatusCode)
	}
	if got := gwA.received(sip.INVITE); len(got) != 1 {
		t.Errorf("call 2 dialed the cooling gw-a: %d INVITEs, want still 1", len(got))
	}
	if got := gwB.received(sip.INVITE); len(got) != 2 {
		t.Errorf("gw-b saw %d INVITEs, want 2", len(got))
	}
	hangupPSTN(t, h, res)

	// Call 3: now gw-b is sick too — its silent attempt earns it its own
	// cooldown — and with every candidate cooling there is no healthy
	// alternative to prefer. Nothing connected, so FreeSWITCH hears 408.
	gwB.setInviteHook(gwB.silentHook())
	res = bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 408 {
		t.Fatalf("call 3: got %d, want 408 Request Timeout", res.StatusCode)
	}
	if got := gwB.received(sip.INVITE); len(got) != 3 {
		t.Errorf("gw-b saw %d INVITEs, want 3", len(got))
	}
	if got := gwA.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-a saw %d INVITEs, want still 1 (still cooling)", len(got))
	}
	waitForRelease(t, h)

	// Call 4: BOTH gateways are cooling now, so the trunk must dial anyway
	// — in route order: gw-a first (its attempt burns its budget again),
	// then gw-b, which is answering again and connects the call.
	gwB.setInviteHook(gwB.answerHook(200, true))
	res = bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 200 {
		t.Fatalf("call 4: got %d, want 200 — all-cooled calls must still be attempted", res.StatusCode)
	}
	if got := gwA.received(sip.INVITE); len(got) != 2 {
		t.Errorf("gw-a saw %d INVITEs, want 2 (dialed despite its cooldown)", len(got))
	}
	if got := gwB.received(sip.INVITE); len(got) != 4 {
		t.Errorf("gw-b saw %d INVITEs, want 4", len(got))
	}
	hangupPSTN(t, h, res)
}

// Early media across a failover: the first gateway answers 180 with an SDP
// and streams audio — FreeSWITCH hears it — then falls silent and burns its
// attempt budget. The winner's 200 re-latches the media anchor: the public
// latch, hardened by the failed gateway's own packets, is re-armed to the
// winner (a hijack would refuse it), and the answer FreeSWITCH finally gets
// carries the WINNER's codec set — PCMA, which the failed gateway never
// offered.
func TestPSTNFailoverRelatchesMedia(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "300ms", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gw1, gw2 := gws["gw-a"], gws["gw-b"]

	// The endpoints' media sockets, bound before the call on the ports
	// their SDP will advertise.
	gw1RTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: gw1.rtpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer gw1RTP.Close()
	gw2RTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: gw2.rtpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer gw2RTP.Close()
	fsRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: h.fs.rtpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer fsRTP.Close()

	// gw-a: early media — a body-bearing 180 offering only PCMU (so the
	// winner's PCMA is distinguishable in the final answer), then a short
	// audio stream from its advertised RTP port. The stream is what makes
	// the test mean anything: the public latch hardens only on real
	// inbound packets, so without it the winner's answer would seed a
	// never-latched relay and the failover re-latch would go unexercised.
	gw1.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		body := fmt.Sprintf("v=0\r\no=gw-a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n", gw1.rtpPort)
		res := sip.NewResponseFromRequest(req, 180, "Ringing", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = tx.Respond(res)
		// The offer is parsed here, synchronously: the hook's request may
		// be touched by the stack once it returns, and the goroutine only
		// needs the SBC's public media port.
		offer, err := sdp.Parse(req.Body())
		if err != nil {
			return true
		}
		sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: offer.Audio.Port}
		// 40 × 10ms = 400ms of audio: longer than the 300ms attempt budget
		// plus its 300ms drain, so the stream has ENDED before the winner
		// answers — a stream still running could re-latch the anchor away
		// from the winner mid-call.
		go func() {
			pkt := rtpPacket(0, 300, 160)
			for i := 0; i < 40; i++ {
				if _, err := gw1RTP.WriteToUDP(pkt, sbcPublic); err != nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		return true
	})
	// gw-b: the winner, answering 200 with PCMU+PCMA+DTMF — a codec set
	// only it offers.
	gw2.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		body := fmt.Sprintf("v=0\r\no=gw-b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"+
			"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=sendrecv\r\n", gw2.rtpPort)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(gw2.addr)}})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
		return true
	})

	res := bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 200 {
		t.Fatalf("bridged call: got %d, want 200", res.StatusCode)
	}

	// gw-a's attempt burned its budget: it must have been cancelled, and
	// the winner is gw-b.
	if cans := gw1.waitFor(sip.CANCEL, 1, 5*time.Second); len(cans) != 1 {
		t.Errorf("gw-a saw %d CANCELs, want 1", len(cans))
	}
	if got := gw1.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-a saw %d INVITEs, want 1", len(got))
	}
	if got := gw2.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-b saw %d INVITEs, want 1", len(got))
	}

	// FreeSWITCH heard gw-a's early media: its socket holds packets from
	// the failed gateway's stream. (The stream ended well before gw-b
	// answered, so everything in the socket is gw-a's.)
	early := 0
	_ = fsRTP.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 2000)
	for {
		n, _, err := fsRTP.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n > 0 {
			early++
		}
	}
	if early == 0 {
		t.Error("FreeSWITCH never heard gw-a's early media")
	}
	_ = fsRTP.SetReadDeadline(time.Time{})

	// The answer FreeSWITCH got is the WINNER's negotiation: PCMA, which
	// only gw-b offered.
	answer, err := sdp.Parse(res.Body())
	if err != nil {
		t.Fatalf("answer to FreeSWITCH unparseable: %v\n%s", err, res.Body())
	}
	if got := sdp.Describe(answer.Audio.Codecs); !strings.Contains(got, "8 PCMA/8000") {
		t.Errorf("answer codecs = %s, want the winner's PCMA", got)
	}

	// Media now flows both ways with the WINNING gateway: the anchor
	// followed the call across the failover. (On loopback both gateways
	// share an IP, so exclusivity cannot be asserted — only that the
	// winner's media flows, which a stuck latch would break.)
	inv := gw2.waitFor(sip.INVITE, 1, 3*time.Second)
	offer, err := sdp.Parse(inv[0].Body())
	if err != nil {
		t.Fatalf("offer to gw-b unparseable: %v", err)
	}
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: offer.Audio.Port}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answer.Audio.Port}
	if !relayReaches(t, gw2RTP, sbcPublic, fsRTP, rtpPacket(0, 400, 160)) {
		t.Fatal("gw-b → FreeSWITCH audio never arrived (latch not re-pointed)")
	}
	if !relayReaches(t, fsRTP, sbcPrivate, gw2RTP, rtpPacket(0, 500, 160)) {
		t.Fatal("FreeSWITCH → gw-b audio never arrived")
	}

	// The dialog rides the winner to the end: the switch's ACK and hangup
	// both reach gw-b.
	if acks := gw2.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Errorf("gw-b saw %d ACKs, want 1", len(acks))
	}
	hangupPSTN(t, h, res)
	if byes := gw2.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
		t.Errorf("gw-b saw %d BYEs, want 1", len(byes))
	}
}

// A FreeSWITCH CANCEL lands while the first attempt is ringing: the stack
// answers the CANCEL and finalises the INVITE, the proxy's CANCEL bridge
// fires wholeCancel — the attempt in flight gets its own CANCEL — and the
// series stops: the next gateway is never dialed.
func TestPSTNCancelDuringAttemptStopsTheSeries(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwA, gwB := gws["gw-a"], gws["gw-b"]
	gwA.setInviteHook(gwA.silentHook())
	gwB.setInviteHook(gwB.answerHook(200, true))

	ruri := sip.Uri{User: "12345", Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	invite, final := h.fs.callAsync(t, ruri, h.publicUDP, phoneOfferSDP(h.fs.rtpPort))

	// Let the first attempt reach its gateway, then give up the way a
	// dialplan's answer timeout does.
	if invs := gwA.waitFor(sip.INVITE, 1, 5*time.Second); len(invs) != 1 {
		t.Fatalf("gw-a saw %d INVITEs, want 1", len(invs))
	}
	h.fs.cancelCall(t, invite, h.publicUDP)

	// The in-flight attempt is cancelled toward its own gateway...
	if cans := gwA.waitFor(sip.CANCEL, 1, 5*time.Second); len(cans) != 1 {
		t.Errorf("gw-a saw %d CANCELs, want 1", len(cans))
	}
	// ...and FreeSWITCH's INVITE finalises (the exact code is the stack's
	// to choose; RFC 3261 §9.2 expects 487).
	select {
	case res := <-final:
		if res == nil {
			t.Fatal("the INVITE transaction never finalised after CANCEL")
		}
		if res.StatusCode != 487 {
			t.Logf("FreeSWITCH saw final response %d (487 expected)", res.StatusCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the INVITE transaction never finalised after CANCEL")
	}
	// ...and the series stops: gw-b is never dialed.
	if got := gwB.waitFor(sip.INVITE, 1, 300*time.Millisecond); len(got) != 0 {
		t.Errorf("gw-b saw %d INVITEs, want 0 — the series must stop on cancel", len(got))
	}
	waitForRelease(t, h)
}

// An answer whose media cannot be anchored does not end the call: the
// gateway that sent it is ACKed and BYEd — it believes it has a live dialog
// and would sit retransmitting its 200 — and the series dials the next
// gateway, whose answer reaches FreeSWITCH.
func TestPSTNUnanchorableAnswerFailsOver(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwA, gwB := gws["gw-a"], gws["gw-b"]
	// gw-a answers 200 with a codec FreeSWITCH never offered (opus): the
	// media cannot be anchored.
	gwA.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		body := "v=0\r\no=gw-a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
			"m=audio 9998 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n"
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = tx.Respond(res)
		return true
	})
	gwB.setInviteHook(gwB.answerHook(200, true))

	res := bridgePSTNCall(t, h, "12345")
	if res.StatusCode != 200 {
		t.Fatalf("bridged call: got %d, want 200 from gw-b", res.StatusCode)
	}
	// gw-a's unanchorable 2xx was completed and torn down...
	if acks := gwA.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Errorf("gw-a saw %d ACKs, want 1", len(acks))
	}
	if byes := gwA.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
		t.Errorf("gw-a saw %d BYEs, want 1", len(byes))
	}
	// ...and the call went on to the next gateway, once each.
	if got := gwA.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-a saw %d INVITEs, want 1", len(got))
	}
	if got := gwB.received(sip.INVITE); len(got) != 1 {
		t.Errorf("gw-b saw %d INVITEs, want 1", len(got))
	}
	hangupPSTN(t, h, res)
}

// ---------------------------------------------------------------------
// The cancelled bridged call: the gateway's 487 must still be ACKed
// ---------------------------------------------------------------------

// rawGateway is a carrier gateway that speaks SIP/UDP by hand over its own
// socket. The fakeSwitch cannot play this part: its sipgo server transaction
// answers a matched CANCEL with 200 and the INVITE's 487 in one breath, and a
// 487 that close to the CANCEL would race the very window this test exists to
// exercise. A real carrier takes tens of milliseconds to send its 487, after
// it has torn its own INVITE transaction down — that timing is the point, so
// this gateway controls it.
type rawGateway struct {
	t    *testing.T
	addr string
	conn *net.UDPConn

	// afterCancel is how long the gateway waits after answering a CANCEL
	// before it 487s the INVITE: inside pstnDrain, but far enough after the
	// SBC's own cancel handling that a pump which does not drain has already
	// returned.
	afterCancel time.Duration

	mu   sync.Mutex
	seen []rawSeen
}

// rawSeen is one request the gateway received, with the source it came from
// (where a response for it must go).
type rawSeen struct {
	req *sip.Request
	src *net.UDPAddr
}

func startRawGateway(t *testing.T, addr string, afterCancel time.Duration) *rawGateway {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatalf("raw gateway %s: %v", addr, err)
	}
	g := &rawGateway{t: t, addr: addr, conn: conn, afterCancel: afterCancel}
	t.Cleanup(g.stop)
	go g.serve()
	return g
}

func (g *rawGateway) stop() { _ = g.conn.Close() }

func (g *rawGateway) serve() {
	buf := make([]byte, 64<<10)
	for {
		n, src, err := g.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg, err := sip.ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		req, ok := msg.(*sip.Request)
		if !ok {
			continue
		}

		g.mu.Lock()
		g.seen = append(g.seen, rawSeen{req: req.Clone(), src: src})
		// The 487 belongs to the INVITE's exchange, so it must echo that
		// INVITE's Via, From, To, Call-ID and CSeq — remember which one the
		// CANCEL is cancelling.
		var invite *rawSeen
		if req.Method == sip.CANCEL {
			for i := len(g.seen) - 1; i >= 0; i-- {
				if g.seen[i].req.Method == sip.INVITE {
					invite = &g.seen[i]
					break
				}
			}
		}
		g.mu.Unlock()

		switch req.Method {
		case sip.INVITE:
			// Ring, as a carrier does while it sets the call up. Bodyless:
			// the SBC negotiates media only on a body-bearing response.
			g.respond(req, src, 180, "Ringing", nil)
		case sip.CANCEL:
			// RFC 3261 §9.2: answer the CANCEL, then terminate the INVITE —
			// but a beat later, which is exactly what the SBC's drain exists
			// to cover.
			g.respond(req, src, 200, "OK", nil)
			if invite == nil {
				continue
			}
			time.Sleep(g.afterCancel)
			g.respond(invite.req, invite.src, 487, "Request Terminated", nil)
		}
	}
}

// respond writes one response for a request the gateway received, to the
// source the request came from.
func (g *rawGateway) respond(req *sip.Request, dst *net.UDPAddr, code int, reason string, body []byte) {
	res := sip.NewResponseFromRequest(req, code, reason, body)
	if body != nil {
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	}
	if _, err := g.conn.WriteToUDP([]byte(res.String()), dst); err != nil {
		g.t.Logf("raw gateway %s: %d response: %v", g.addr, code, err)
	}
}

// received returns every request of a method the gateway has seen.
func (g *rawGateway) received(method sip.RequestMethod) []*sip.Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []*sip.Request
	for _, s := range g.seen {
		if s.req.Method == method {
			out = append(out, s.req)
		}
	}
	return out
}

// waitForAckBranch returns the ACKs whose top Via branch matches branch. A
// non-2xx final's ACK is generated by the transaction layer and echoes the
// INVITE's own branch (RFC 3261 §17.1.1.3); an ACK a proxy relayed carries a
// branch of its own, so matching on the method alone could count the wrong
// message.
func (g *rawGateway) waitForAckBranch(branch string, d time.Duration) []*sip.Request {
	deadline := time.Now().Add(d)
	for {
		var out []*sip.Request
		for _, r := range g.received(sip.ACK) {
			if b, _ := r.Via().Params.Get("branch"); b == branch {
				out = append(out, r)
			}
		}
		if len(out) > 0 || time.Now().After(deadline) {
			return out
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (g *rawGateway) waitFor(method sip.RequestMethod, n int, d time.Duration) []*sip.Request {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if got := g.received(method); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return g.received(method)
}

// TestPSTNCancelACKsGateway487 is the regression test for the cancelled
// bridged call: FreeSWITCH gives up while the carrier is still ringing, the
// SBC relays the CANCEL — and the carrier's 487, which arrives only after the
// CANCEL has already ended the call, must still be ACKed (RFC 3261
// §17.1.1.3). Without that ACK the carrier retransmits its 487 until Timer H,
// and every retransmission is logged as an unhandled response.
func TestPSTNCancelACKsGateway487(t *testing.T) {
	gwAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	// The 487 lands well inside pstnDrain but long after the SBC's cancel
	// handling has returned — the race that leaves it unACKed when the pump
	// returns without draining.
	gw := startRawGateway(t, gwAddr, 100*time.Millisecond)
	h := startHarnessCfg(t, false, "127.0.0.1", "127.0.0.2", func(pubUDP int) string {
		return fmt.Sprintf("  pstn:\n    address: %s\n    match: 127.0.0.1:%d\n", gwAddr, pubUDP)
	})

	ruri := sip.Uri{User: "12345", Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	invite, final := h.fs.callAsync(t, ruri, h.publicUDP, phoneOfferSDP(h.fs.rtpPort))

	// The bridged INVITE reached the carrier and the carrier is ringing.
	invs := gw.waitFor(sip.INVITE, 1, 5*time.Second)
	if len(invs) != 1 {
		t.Fatalf("the gateway saw %d INVITEs, want 1", len(invs))
	}
	branch, _ := invs[0].Via().Params.Get("branch")

	// FreeSWITCH's dialplan gives up mid-ring.
	h.fs.cancelCall(t, invite, h.publicUDP)

	// The SBC relayed the CANCEL and the gateway answered it; the gateway's
	// 487 for the INVITE follows afterCancel later.
	if cans := gw.waitFor(sip.CANCEL, 1, 5*time.Second); len(cans) != 1 {
		t.Fatalf("the gateway saw %d CANCELs, want 1", len(cans))
	}

	// The assertion: the ACK for that 487 must reach the gateway. It is the
	// transaction layer's, so it carries the INVITE's own branch.
	if acks := gw.waitForAckBranch(branch, 3*time.Second); len(acks) != 1 {
		t.Errorf("the gateway saw %d ACKs carrying its INVITE's branch, want 1 — it would retransmit its 487 until Timer H", len(acks))
	}

	// FreeSWITCH's INVITE transaction still finalised (sipgo answers the
	// CANCEL and 487s the INVITE itself), and nothing leaked.
	select {
	case res := <-final:
		if res == nil {
			t.Fatal("the INVITE transaction never finalised after CANCEL")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the INVITE transaction never finalised after CANCEL")
	}
	waitForRelease(t, h)
}
