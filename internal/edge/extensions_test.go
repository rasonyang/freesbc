package edge

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// headerTokens is every comma-separated token of m's headers named name
// (any case), upper-cased.
func headerTokens(m interface{ GetHeaders(string) []sip.Header }, name string) map[string]bool {
	toks := map[string]bool{}
	for _, h := range m.GetHeaders(name) {
		for _, tok := range strings.Split(h.Value(), ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				toks[strings.ToUpper(tok)] = true
			}
		}
	}
	return toks
}

// assertExtensionsAdvertised checks that m advertises what the proxy
// carries (PRACK and UPDATE included) and still has 100rel and timer in
// Supported, and that a method it does not carry (PUBLISH) was dropped from
// Allow.
func assertExtensionsAdvertised(t *testing.T, what string, m interface{ GetHeaders(string) []sip.Header }) {
	t.Helper()
	allow := headerTokens(m, "Allow")
	if allow["PUBLISH"] {
		t.Errorf("%s: Allow still advertises PUBLISH: %v", what, allow)
	}
	for _, method := range []string{"INVITE", "BYE", "PRACK", "UPDATE"} {
		if !allow[method] {
			t.Errorf("%s: Allow lost %s: %v", what, method, allow)
		}
	}
	supported := headerTokens(m, "Supported")
	for _, tok := range []string{"100REL", "TIMER"} {
		if !supported[tok] {
			t.Errorf("%s: Supported lost %s: %v", what, tok, supported)
		}
	}
}

func extensionHeaders() []sip.Header {
	return []sip.Header{
		sip.NewHeader("Allow", "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, PUBLISH"),
		sip.NewHeader("Supported", "100rel, timer"),
	}
}

// audit: P2-EDG-010
//
// The proxy carries PRACK and UPDATE, so Supported: 100rel and Allow:
// PRACK/UPDATE pass between the ends and only methods it cannot carry are
// dropped. A call from a phone: the INVITE FreeSWITCH receives and the 200
// the phone receives both advertise them.
func TestAuditPRACKUpdateAdvertisedPhoneToFS(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		for _, hd := range extensionHeaders() {
			res.AppendHeader(hd)
		}
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
		return true
	})
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(40000))
	for _, hd := range extensionHeaders() {
		invite.AppendHeader(hd)
	}
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	sendAck(t, phone, invite, res, h.publicUDP)
	up := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(up) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs", len(up))
	}
	assertExtensionsAdvertised(t, "INVITE toward FreeSWITCH", up[0])
	assertExtensionsAdvertised(t, "200 toward the phone", res)
}

// audit: P2-EDG-010
//
// The other direction: FreeSWITCH calls a registered phone. The INVITE the
// phone receives and the 200 FreeSWITCH receives are treated the same way.
func TestAuditPRACKUpdateAdvertisedFSToPhone(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	var (
		mu  sync.Mutex
		got *sip.Request
	)
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		mu.Lock()
		got = req.Clone()
		mu.Unlock()
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(40002)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		for _, hd := range extensionHeaders() {
			res.AppendHeader(hd)
		}
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
	})
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort), extensionHeaders()...)
	if res.StatusCode != 200 {
		t.Fatalf("inbound INVITE: got %d, want 200", res.StatusCode)
	}
	h.fs.sendAckTo2xx(t, res)
	mu.Lock()
	defer mu.Unlock()
	if got == nil {
		t.Fatal("the phone never saw the INVITE")
	}
	assertExtensionsAdvertised(t, "INVITE toward the phone", got)
	assertExtensionsAdvertised(t, "200 toward FreeSWITCH", res)
}

// An INVITE that REQUIRES 100rel is no longer refused: Require passes to
// FreeSWITCH unchanged.
func TestRequire100relPassesThrough(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(40004))
	invite.AppendHeader(sip.NewHeader("Require", "100rel"))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE with Require: 100rel: got %d, want 200", res.StatusCode)
	}
	up := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(up) != 1 {
		t.Fatalf("FreeSWITCH saw %d INVITEs, want 1", len(up))
	}
	if req := headerTokens(up[0], "Require"); !req["100REL"] {
		t.Errorf("Require: 100rel did not reach FreeSWITCH: %v", up[0].GetHeaders("Require"))
	}
}

// PRACK and UPDATE outside any dialog are answered 481: there is nothing to
// acknowledge or refresh, and the proxy never guesses a switch for them.
func TestPRACKAndUpdateWithoutDialog481(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	for _, m := range []sip.RequestMethod{sip.PRACK, sip.UPDATE} {
		req := phone.buildInvite("1001", "2002", "example.com", "")
		req.Method = m
		req.CSeq().MethodName = m
		res := phone.do(t, req, h.publicUDP)
		if res.StatusCode != 481 {
			t.Errorf("%s: got %d, want 481", m, res.StatusCode)
		}
	}
	if n := len(h.fs.received(sip.PRACK)) + len(h.fs.received(sip.UPDATE)); n != 0 {
		t.Errorf("%d dialog-less PRACK/UPDATE reached the switch", n)
	}
}

func TestFilterTokenHeader(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{Host: "example.com"})
	req.AppendHeader(sip.NewHeader("k", "100rel"))
	req.AppendHeader(sip.NewHeader("Supported", "timer, 100REL, replaces"))
	req.AppendHeader(sip.NewHeader("allow", "INVITE, publish"))
	req.AppendHeader(sip.NewHeader("Allow", "Prack, Update"))
	sanitizeExtensions(req)
	// Supported is end to end and is never touched.
	if hs := req.GetHeaders("k"); len(hs) != 1 || hs[0].Value() != "100rel" {
		t.Errorf("compact Supported = %v, want it untouched", hs)
	}
	sup := req.GetHeaders("Supported")
	if len(sup) != 1 || sup[0].Value() != "timer, 100REL, replaces" {
		t.Errorf("Supported = %v, want it untouched", sup)
	}
	allow := req.GetHeaders("Allow")
	if len(allow) != 1 || allow[0].Value() != "INVITE, Prack, Update" {
		t.Errorf("Allow = %v, want one header \"INVITE, Prack, Update\"", allow)
	}

	// Only methods the proxy cannot carry: the header goes away rather
	// than being left empty.
	req = sip.NewRequest(sip.INVITE, sip.Uri{Host: "example.com"})
	req.AppendHeader(sip.NewHeader("Allow", "PUBLISH"))
	sanitizeExtensions(req)
	if hs := req.GetHeaders("Allow"); len(hs) != 0 {
		t.Errorf("empty Allow left behind: %v", hs)
	}

	// Nothing to drop: the headers are left exactly as they were.
	req = sip.NewRequest(sip.INVITE, sip.Uri{Host: "example.com"})
	orig := sip.NewHeader("Allow", "INVITE,PRACK")
	req.AppendHeader(orig)
	sanitizeExtensions(req)
	if hs := req.GetHeaders("Allow"); len(hs) != 1 || hs[0] != orig {
		t.Errorf("an unchanged header was rewritten: %v", hs)
	}
}
