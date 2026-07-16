package sig

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

func reqWith(headers ...sip.Header) *sip.Request {
	r := sip.NewRequest(sip.INVITE, sip.Uri{Scheme: "sip", User: "x", Host: "h"})
	for _, h := range headers {
		r.AppendHeader(h)
	}
	return r
}

func TestHeaderSeconds(t *testing.T) {
	r := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	if got := headerSeconds(r, "Session-Expires"); got != 1800*time.Second {
		t.Errorf("got %v, want 1800s", got)
	}
	r2 := reqWith(sip.NewHeader("Min-SE", "90"))
	if got := headerSeconds(r2, "Min-SE"); got != 90*time.Second {
		t.Errorf("got %v, want 90s", got)
	}
	if got := headerSeconds(reqWith(), "Session-Expires"); got != 0 {
		t.Errorf("absent header should be 0, got %v", got)
	}
	if got := headerSeconds(reqWith(sip.NewHeader("Session-Expires", "junk")), "Session-Expires"); got != 0 {
		t.Errorf("unparseable should be 0, got %v", got)
	}
}

func TestRequires100rel(t *testing.T) {
	if !requires100rel(reqWith(sip.NewHeader("Require", "100rel"))) {
		t.Error("Require: 100rel should be detected")
	}
	if !requires100rel(reqWith(sip.NewHeader("Require", "timer, 100rel"))) {
		t.Error("Require: timer, 100rel should be detected")
	}
	if requires100rel(reqWith(sip.NewHeader("Supported", "100rel"))) {
		t.Error("Supported (not Require) must not count")
	}
	if requires100rel(reqWith()) {
		t.Error("no Require header → false")
	}
}

func TestNegotiateSE(t *testing.T) {
	se, min := 1800*time.Second, 90*time.Second
	if got := negotiateSE(3600*time.Second, 0, se, min); got != 1800*time.Second {
		t.Errorf("caller higher → ours (1800s), got %v", got)
	}
	if got := negotiateSE(600*time.Second, 0, se, min); got != 600*time.Second {
		t.Errorf("caller lower → caller (600s), got %v", got)
	}
	if got := negotiateSE(30*time.Second, 0, se, min); got != 90*time.Second {
		t.Errorf("below floor → min_se (90s), got %v", got)
	}
	if got := negotiateSE(0, 0, se, min); got != 1800*time.Second {
		t.Errorf("no caller SE → ours (1800s), got %v", got)
	}
	// RFC 4028 §9: never below the caller's own Min-SE, even when that
	// exceeds our configured session_expires.
	if got := negotiateSE(7200*time.Second, 3600*time.Second, se, min); got != 3600*time.Second {
		t.Errorf("caller Min-SE 3600s > ours 1800s → floor at 3600s, got %v", got)
	}
	if got := negotiateSE(600*time.Second, 300*time.Second, se, min); got != 600*time.Second {
		t.Errorf("caller SE 600s above caller Min-SE 300s → 600s, got %v", got)
	}
}

func TestSessionExpiresHeader(t *testing.T) {
	h := sessionExpiresHeader(1800*time.Second, "uac")
	if h.Name() != "Session-Expires" || h.Value() != "1800;refresher=uac" {
		t.Errorf("got %s: %q", h.Name(), h.Value())
	}
}

func TestIsRefreshReInvite(t *testing.T) {
	established := []byte("v=0\r\nm=audio 40000 RTP/AVP 0\r\n")
	// In-dialog (To-tag) + Session-Expires + same SDP → refresh.
	refresh := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	toHdr := &sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: "y", Host: "h"}, Params: sip.NewParams()}
	toHdr.Params.Add("tag", "abc")
	refresh.ReplaceHeader(toHdr)
	refresh.SetBody(established)
	if !isRefreshReInvite(refresh, established) {
		t.Error("in-dialog + Session-Expires + same SDP should be a refresh")
	}
	// Same but different SDP → media change, not a refresh.
	media := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	toHdr2 := &sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: "y", Host: "h"}, Params: sip.NewParams()}
	toHdr2.Params.Add("tag", "abc")
	media.ReplaceHeader(toHdr2)
	media.SetBody([]byte("v=0\r\nm=audio 50000 RTP/AVP 0\r\n"))
	if isRefreshReInvite(media, established) {
		t.Error("changed SDP is a media re-INVITE, not a refresh")
	}
	// No Session-Expires → not a refresh.
	noSE := reqWith()
	toHdr3 := &sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: "y", Host: "h"}, Params: sip.NewParams()}
	toHdr3.Params.Add("tag", "abc")
	noSE.ReplaceHeader(toHdr3)
	noSE.SetBody(established)
	if isRefreshReInvite(noSE, established) {
		t.Error("no Session-Expires → not a refresh")
	}
}

// TestIsRefreshReInviteToleratesOriginVersionBump is Fix 4: a real UAC
// refresh commonly bumps the o= line's version number on every re-offer
// (RFC 3264 §8) even when the rest of the SDP — in particular c=/m=, the
// lines that actually describe the media — is unchanged. Before Fix 4,
// isRefreshReInvite compared raw bytes, so this legitimate refresh would be
// misclassified as a media change and answered 501 instead of 200,
// effectively breaking session-timer refreshes against any UAC that does
// this (which real stacks do).
func TestIsRefreshReInviteToleratesOriginVersionBump(t *testing.T) {
	established := []byte("v=0\r\no=- 1 1 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 203.0.113.5\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n")
	// Same SDP, only the o= line's version field bumped 1 → 2 (and the
	// session-id also differs, as some stacks do on every re-offer).
	bumped := []byte("v=0\r\no=- 1 2 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 203.0.113.5\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n")

	refresh := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	toHdr := &sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: "y", Host: "h"}, Params: sip.NewParams()}
	toHdr.Params.Add("tag", "abc")
	refresh.ReplaceHeader(toHdr)
	refresh.SetBody(bumped)
	if !isRefreshReInvite(refresh, established) {
		t.Error("o=-version-only change should still be recognized as a refresh")
	}

	// A genuine media change (c= differs) alongside the o= bump must still
	// be rejected — ignoring o= must not make the comparison too loose.
	cChanged := []byte("v=0\r\no=- 1 2 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n")
	cReq := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	toHdr2 := &sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: "y", Host: "h"}, Params: sip.NewParams()}
	toHdr2.Params.Add("tag", "abc")
	cReq.ReplaceHeader(toHdr2)
	cReq.SetBody(cChanged)
	if isRefreshReInvite(cReq, established) {
		t.Error("c= change alongside an o= bump must still be a media change, not a refresh")
	}

	// A genuine m= change alongside the o= bump must also still be rejected.
	mChanged := []byte("v=0\r\no=- 1 2 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 203.0.113.5\r\nt=0 0\r\nm=audio 50000 RTP/AVP 0\r\n")
	mReq := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	toHdr3 := &sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: "y", Host: "h"}, Params: sip.NewParams()}
	toHdr3.Params.Add("tag", "abc")
	mReq.ReplaceHeader(toHdr3)
	mReq.SetBody(mChanged)
	if isRefreshReInvite(mReq, established) {
		t.Error("m= change alongside an o= bump must still be a media change, not a refresh")
	}
}
