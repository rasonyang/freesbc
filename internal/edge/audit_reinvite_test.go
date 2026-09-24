package edge

// Regression tests for edge re-INVITE handling (issue #24).

import (
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// audit: P2-EDG-024
// Re-INVITE glare: the phone and FreeSWITCH re-INVITE each other at the
// same time, and each far end answers first in a 183 and then restates the
// answer in its 200. Each 200 must carry the answer built for ITS OWN
// transaction — the phone's on the public anchor, FreeSWITCH's on the
// private one. Restating whichever answer was built last hands one side
// the other plane's address (and, for a browser, would hand FreeSWITCH ICE
// and DTLS). Run under -race, the concurrent codec updates are checked too.
func TestAuditReInviteGlareKeepsEachAnswer(t *testing.T) {
	h := startHarness(t, false)
	fs183 := make(chan struct{})
	phone183 := make(chan struct{})
	fs200 := make(chan struct{})
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, func(req *sip.Request, tx sip.ServerTransaction) {
		// The phone's re-INVITE: answer in a 183, then — once the phone has
		// answered FreeSWITCH's crossing re-INVITE in a 183 of its own —
		// restate it in the 200.
		body := []byte(h.fs.answerSDP(req))
		early := sip.NewResponseFromRequest(req, 183, "Session Progress", body)
		early.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = tx.Respond(early)
		close(fs183)
		select {
		case <-phone183:
		case <-time.After(5 * time.Second):
		}
		time.Sleep(200 * time.Millisecond)
		ok := sip.NewResponseFromRequest(req, 200, "OK", body)
		ok.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		ok.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		ok.To().Params.Add("tag", fsip.ToTag(early))
		_ = tx.Respond(ok)
		close(fs200)
	}))
	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	fsTag := <-tags
	waitForDialog(t, h, fsip.CallID(invite))
	upInv := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	first, _ := sdp.Parse(res.Body())
	up, _ := sdp.Parse(upInv[0].Body())
	publicPort, privatePort := first.Audio.Port, up.Audio.Port

	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		// FreeSWITCH's re-INVITE: 183 now, the restating 200 only after
		// FreeSWITCH's 200 to the phone's own re-INVITE has gone out.
		body := []byte(phoneOfferSDP(auditUDPPort(phoneRTP)))
		early := sip.NewResponseFromRequest(req, 183, "Session Progress", body)
		early.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = tx.Respond(early)
		close(phone183)
		select {
		case <-fs200:
		case <-time.After(5 * time.Second):
		}
		time.Sleep(200 * time.Millisecond)
		ok := sip.NewResponseFromRequest(req, 200, "OK", body)
		ok.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		ok.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		ok.To().Params.Add("tag", fsip.ToTag(early))
		_ = tx.Respond(ok)
	})

	phoneDone := make(chan *sip.Response, 1)
	go func() {
		_, r := auditPhoneReInvite(t, h, phone, invite, res, 2, phoneOfferSDP(auditUDPPort(phoneRTP)))
		phoneDone <- r
	}()
	select {
	case <-fs183:
	case <-time.After(5 * time.Second):
		t.Fatal("FreeSWITCH never saw the phone's re-INVITE")
	}
	fsRes := auditInDialogWithBody(t, h.fs, sip.INVITE, upInv[0], fsTag, 2,
		strings.Replace(h.fs.answerSDP(upInv[0]), "o=FreeSWITCH 1 1", "o=FreeSWITCH 1 2", 1))
	var phoneRes *sip.Response
	select {
	case phoneRes = <-phoneDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the phone's re-INVITE never completed")
	}
	if phoneRes.StatusCode != 200 || fsRes.StatusCode != 200 {
		t.Fatalf("re-INVITEs: phone got %d, FreeSWITCH got %d", phoneRes.StatusCode, fsRes.StatusCode)
	}
	toPhone, err := sdp.Parse(phoneRes.Body())
	if err != nil {
		t.Fatalf("answer to the phone: %v", err)
	}
	toFS, err := sdp.Parse(fsRes.Body())
	if err != nil {
		t.Fatalf("answer to FreeSWITCH: %v", err)
	}
	if toPhone.Audio.Port != publicPort {
		t.Errorf("P2-EDG-024 confirmed: the phone's re-INVITE 200 carries port %d, want its public anchor %d (private anchor is %d)",
			toPhone.Audio.Port, publicPort, privatePort)
	}
	if toFS.Audio.Port != privatePort {
		t.Errorf("P2-EDG-024 confirmed: FreeSWITCH's re-INVITE 200 carries port %d, want its private anchor %d (public anchor is %d)",
			toFS.Audio.Port, privatePort, publicPort)
	}
}
