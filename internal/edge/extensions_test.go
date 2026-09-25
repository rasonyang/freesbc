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

// assertExtensionsSanitized checks that m advertises neither PRACK/UPDATE
// nor 100rel, and still carries what the proxy can do (INVITE, timer).
func assertExtensionsSanitized(t *testing.T, what string, m interface{ GetHeaders(string) []sip.Header }) {
	t.Helper()
	allow := headerTokens(m, "Allow")
	for _, method := range []string{"PRACK", "UPDATE", "REFER"} {
		if allow[method] {
			t.Errorf("%s: Allow still advertises %s: %v", what, method, allow)
		}
	}
	if !allow["INVITE"] || !allow["BYE"] {
		t.Errorf("%s: Allow lost methods the proxy carries: %v", what, allow)
	}
	supported := headerTokens(m, "Supported")
	if supported["100REL"] {
		t.Errorf("%s: Supported still advertises 100rel: %v", what, supported)
	}
	if !supported["TIMER"] {
		t.Errorf("%s: Supported lost timer, which re-INVITE refreshes still serve: %v", what, supported)
	}
}

func extensionHeaders() []sip.Header {
	return []sip.Header{
		sip.NewHeader("Allow", "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, REFER"),
		sip.NewHeader("Supported", "100rel, timer"),
	}
}

// audit: P2-EDG-010
//
// The proxy answers PRACK and UPDATE with 405, so neither end may be told
// the other supports them: a callee that saw 100rel could send a reliable
// 18x whose PRACK never arrives (RFC 3262 §3), and a refresher that saw
// UPDATE could refresh with it and lose the call (RFC 4028 §9). A call
// from a phone: the INVITE FreeSWITCH receives and the 200 the phone
// receives both advertise only what the proxy carries.
func TestAuditPRACKUpdateNotAdvertisedPhoneToFS(t *testing.T) {
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
	assertExtensionsSanitized(t, "INVITE toward FreeSWITCH", up[0])
	assertExtensionsSanitized(t, "200 toward the phone", res)
}

// audit: P2-EDG-010
//
// The other direction: FreeSWITCH calls a registered phone. The INVITE the
// phone receives and the 200 FreeSWITCH receives are sanitised the same
// way.
func TestAuditPRACKUpdateNotAdvertisedFSToPhone(t *testing.T) {
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
	assertExtensionsSanitized(t, "INVITE toward the phone", got)
	assertExtensionsSanitized(t, "200 toward FreeSWITCH", res)
}

// audit: P2-EDG-010
//
// An INVITE that REQUIRES 100rel cannot be honoured through a proxy that
// refuses PRACK: it is answered 420 naming the extension (RFC 3261
// §8.2.2.3), so the caller can retry without it, and it never reaches
// FreeSWITCH.
func TestAuditRequire100relGets420(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(40004))
	invite.AppendHeader(sip.NewHeader("Require", "100rel"))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 420 {
		t.Fatalf("INVITE with Require: 100rel: got %d, want 420", res.StatusCode)
	}
	if u := headerTokens(res, "Unsupported"); !u["100REL"] {
		t.Errorf("420 must name 100rel in Unsupported, got %v", u)
	}
	if n := len(h.fs.received(sip.INVITE)); n != 0 {
		t.Errorf("FreeSWITCH saw %d INVITEs, want 0", n)
	}
}

// PRACK and UPDATE themselves are still refused, with an Allow that does
// not list them.
func TestPRACKAndUpdateStill405(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	for _, m := range []sip.RequestMethod{sip.PRACK, sip.UPDATE} {
		req := phone.buildInvite("1001", "2002", "example.com", "")
		req.Method = m
		req.CSeq().MethodName = m
		res := phone.do(t, req, h.publicUDP)
		if res.StatusCode != 405 {
			t.Errorf("%s: got %d, want 405", m, res.StatusCode)
		}
		if allow := headerTokens(res, "Allow"); allow[string(m)] {
			t.Errorf("%s: the 405's Allow lists it: %v", m, allow)
		}
	}
}

func TestFilterTokenHeader(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{Host: "example.com"})
	req.AppendHeader(sip.NewHeader("k", "100rel"))
	req.AppendHeader(sip.NewHeader("Supported", "timer, 100REL, replaces"))
	req.AppendHeader(sip.NewHeader("allow", "INVITE, update"))
	req.AppendHeader(sip.NewHeader("Allow", "Prack"))
	sanitizeExtensions(req)
	if hs := req.GetHeaders("k"); len(hs) != 0 {
		t.Errorf("compact Supported left behind: %v", hs)
	}
	sup := req.GetHeaders("Supported")
	if len(sup) != 1 || sup[0].Value() != "timer, replaces" {
		t.Errorf("Supported = %v, want one header \"timer, replaces\"", sup)
	}
	allow := req.GetHeaders("Allow")
	if len(allow) != 1 || allow[0].Value() != "INVITE" {
		t.Errorf("Allow = %v, want one header \"INVITE\"", allow)
	}

	// Only 100rel: the header goes away rather than being left empty.
	req = sip.NewRequest(sip.INVITE, sip.Uri{Host: "example.com"})
	req.AppendHeader(sip.NewHeader("Supported", "100rel"))
	sanitizeExtensions(req)
	if hs := req.GetHeaders("Supported"); len(hs) != 0 {
		t.Errorf("empty Supported left behind: %v", hs)
	}

	// Nothing to drop: the headers are left exactly as they were.
	req = sip.NewRequest(sip.INVITE, sip.Uri{Host: "example.com"})
	orig := sip.NewHeader("Supported", "timer,replaces")
	req.AppendHeader(orig)
	sanitizeExtensions(req)
	if hs := req.GetHeaders("Supported"); len(hs) != 1 || hs[0] != orig {
		t.Errorf("an unchanged header was rewritten: %v", hs)
	}
}
