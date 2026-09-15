package edge

import (
	"net"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// TestByeFromUpstreamReachesClientOnWildcardBind drives the hangup
// direction over the production bind shape: the public UDP listener is
// bound to 0.0.0.0 (a random high port here) while the private plane sits
// on 127.0.0.1. FreeSWITCH ends the call and the BYE must still reach the
// phone — a FreeSBC-initiated request toward the phone leaves from the
// public listener, whose configured address is the wildcard, not the
// socket's concrete local address.
//
// The loopback harness used by the other tests binds the public listener
// to 127.0.0.1, where the configured pin and the socket address coincide
// and the outgoing path is exercised with only the easy half of the
// problem. This is the half production actually hits: with the listener on
// 0.0.0.0, a request pinned to the configured address must still find the
// listener's socket (see forward.go prepareForward, which pins the outbound
// request to the side's configured laddr).
func TestByeFromUpstreamReachesClientOnWildcardBind(t *testing.T) {
	h := startHarnessOn(t, false, "0.0.0.0")
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

	// A phone-to-FreeSWITCH call: the outgoing requests toward FreeSWITCH
	// pin the private socket, so this leg is unaffected by the wildcard.
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30501))
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

	// FreeSWITCH hangs up. Its BYE must be relayed to the phone, and the
	// 200 the phone answers must come back to FreeSWITCH — never a locally
	// generated 408.
	byeRes := h.fs.inDialog(t, sip.BYE, upstreamInvites[0], switchTag)
	if byeRes.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d %s, want 200 — the request never left "+
			"the proxy and the phone would keep sending media", byeRes.StatusCode, byeRes.Reason)
	}

	var got *sip.Request
	select {
	case got = <-phone.inbound:
		if got.Method != sip.BYE {
			t.Fatalf("the phone received %s, want BYE", got.Method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the phone never received the BYE — the call would hang until the media watchdog fired")
	}
	// The BYE must leave from the public listener itself: a NAT pinhole
	// admits traffic from the address:port the phone registered to, so a
	// source port that is not the public listener's would be dropped by
	// the phone's NAT and the hangup would still fail in production.
	if srcPort := portOf(got.Source()); srcPort != portOf(h.publicUDP) {
		t.Errorf("BYE arrived from source port %d, want the public listener port %d — "+
			"it left the proxy from the wrong socket", srcPort, portOf(h.publicUDP))
	}
	waitForRelease(t, h)
}

// TestInboundCallAndHangupOnWildcardBind is the other direction the
// wildcard pin broke in production, over the same bind shape: FreeSWITCH
// calls a registered phone (the INVITE leaves through the public listener)
// and then hangs up (the BYE leaves through it again). Both must reach the
// phone from the public listener's own port.
func TestInboundCallAndHangupOnWildcardBind(t *testing.T) {
	h := startHarnessOn(t, false, "0.0.0.0")
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
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
	})

	var ruri sip.Uri
	if err := sip.ParseUri(stored[0], &ruri); err != nil {
		t.Fatalf("stored contact %q unparseable: %v", stored[0], err)
	}
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("inbound INVITE: got %d, want 200", res.StatusCode)
	}

	var invite *sip.Request
	select {
	case got := <-phone.inbound:
		if got.Method != sip.INVITE {
			t.Fatalf("the phone received %s, want INVITE", got.Method)
		}
		invite = got
	case <-time.After(5 * time.Second):
		t.Fatal("the inbound INVITE never reached the phone")
	}
	if srcPort := portOf(invite.Source()); srcPort != portOf(h.publicUDP) {
		t.Errorf("INVITE arrived from source port %d, want the public listener port %d",
			srcPort, portOf(h.publicUDP))
	}

	// FreeSWITCH hangs up first.
	drain(phone.inbound)
	byeRes := fsUacBye(t, h.fs, res)
	if byeRes.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d %s, want 200", byeRes.StatusCode, byeRes.Reason)
	}
	select {
	case got := <-phone.inbound:
		if got.Method != sip.BYE {
			t.Fatalf("the phone received %s, want BYE", got.Method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the BYE from FreeSWITCH never reached the phone")
	}
	waitForRelease(t, h)
}

// fsUacBye sends an in-dialog BYE from the fake switch as the UAC of a
// call IT placed (the role f.call leaves it in), built the way a UAC
// builds one: Request-URI = the stored contact, Route = the Record-Route
// set from the response IN REVERSE (RFC 3261 §12.1.2), From/To copied from
// the final response so both tags match the dialog.
func fsUacBye(t *testing.T, f *fakeSwitch, res *sip.Response) *sip.Response {
	return f.uacBye(t, res)
}
