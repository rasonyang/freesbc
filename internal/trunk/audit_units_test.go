package trunk

// Audit tests (docs/audit/phase3/trunk.md). Each test names the Phase 2
// finding it confirms or refutes. A failing test here is the deliverable:
// it reproduces a defect in production code and must not be "fixed" by
// editing the test.

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/freesbc/freesbc/internal/media"
)

// auditParseRequest parses a raw SIP request the way the transport does, so
// header names are exactly what sipgo's parser produces off the wire.
func auditParseRequest(t *testing.T, raw string) *sip.Request {
	t.Helper()
	msg, err := sip.ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("parse request: %v\n%s", err, raw)
	}
	req, ok := msg.(*sip.Request)
	if !ok {
		t.Fatalf("parsed message is %T, want *sip.Request", msg)
	}
	return req
}

func auditInviteWithHeaders(extra ...string) string {
	lines := []string{
		"INVITE sip:5551234@127.0.0.1:5060 SIP/2.0",
		"Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK-audit",
		"From: <sip:a@127.0.0.1>;tag=f1",
		"To: <sip:b@127.0.0.1>",
		"Call-ID: audit-units",
		"CSeq: 1 INVITE",
		"Max-Forwards: 70",
	}
	lines = append(lines, extra...)
	lines = append(lines, "Content-Length: 0", "", "")
	return strings.Join(lines, "\r\n")
}

// audit: P2-TRK-011
// A challenge whose first "realm=" substring sits inside another parameter
// name (xrealm=) must not be mistaken for the realm. RFC 2617 §1.2 /
// RFC 3261 §25.1: auth-param names are tokens; "xrealm" is not "realm".
func TestAuditChallengeRealmSubstringBypass(t *testing.T) {
	res := sip.NewResponse(401, "Unauthorized")
	res.AppendHeader(sip.NewHeader("WWW-Authenticate",
		`Digest xrealm="trusted", realm="rogue", nonce="n", algorithm=MD5`))
	if got := challengeRealm(res); got != "rogue" {
		t.Fatalf("challengeRealm = %q, want %q (the realm sipgo will actually digest over); "+
			"a pinned realm of %q would pass the pin check", got, "rogue", got)
	}
}

// audit: P2-TRK-011
// Parameter names are case-insensitive (RFC 3261 §7.3.1, RFC 2617 §1.2).
func TestAuditChallengeRealmCaseInsensitiveName(t *testing.T) {
	res := sip.NewResponse(401, "Unauthorized")
	res.AppendHeader(sip.NewHeader("WWW-Authenticate", `Digest REALM="carrier", nonce="n"`))
	if got := challengeRealm(res); got != "carrier" {
		t.Fatalf("challengeRealm = %q, want %q", got, "carrier")
	}
}

// audit: P2-TRK-010
// RFC 4028 §4 defines "x" as the compact form of Session-Expires. A request
// parsed off the wire with "x: 30" must be seen as Session-Expires 30s.
func TestAuditHeaderSecondsCompactSessionExpires(t *testing.T) {
	req := auditParseRequest(t, auditInviteWithHeaders("x: 30"))
	if got := headerSeconds(req, "Session-Expires"); got != 30*time.Second {
		t.Fatalf("headerSeconds(Session-Expires) on compact 'x: 30' = %v, want 30s", got)
	}
}

// audit: P2-TRK-010
// Control: the long form is recognized (proves the compact-form failure
// above is about the name, not the parsing of the value).
func TestAuditHeaderSecondsLongFormControl(t *testing.T) {
	req := auditParseRequest(t, auditInviteWithHeaders("Session-Expires: 30"))
	if got := headerSeconds(req, "Session-Expires"); got != 30*time.Second {
		t.Fatalf("headerSeconds(Session-Expires) = %v, want 30s", got)
	}
}

// audit: P2-TRK-018
// RFC 3261 §25.1 / RFC 4028 §4 delta-seconds: huge values must not wrap
// into a negative or tiny duration.
func TestAuditHeaderSecondsOverflow(t *testing.T) {
	for _, v := range []string{"9223372036854775807", "10000000000000", "9223372037"} {
		req := auditParseRequest(t, auditInviteWithHeaders("Session-Expires: "+v))
		got := headerSeconds(req, "Session-Expires")
		if got < 0 || (got > 0 && got < time.Hour) {
			t.Errorf("headerSeconds(%s) = %v (%d ns): wrapped around instead of clamping", v, got, int64(got))
		}
	}
}

// audit: P2-TRK-012
// RFC 4568 §6.1: a key with an MKI means every SRTP packet carries that MKI.
// The SBC's SRTP context has no MKI support, so such a line must not be
// accepted as a usable plain key.
func TestAuditSDESLineWithMKIRejected(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, media.SDESKeyLen))
	lines := parseCryptoAttrs([]string{"1 AES_CM_128_HMAC_SHA1_80 inline:" + key + "|2^20|1:4"})
	if len(lines) != 0 {
		t.Fatalf("parseCryptoAttrs accepted an MKI-bearing key as plain: %+v", lines)
	}
}

// audit: P2-TRK-012
// RFC 4568 §6.3: unknown/unsupported session parameters (e.g.
// UNENCRYPTED_SRTP) change processing; a line carrying one must not be
// accepted as if it were a plain SDES line.
func TestAuditSDESLineWithSessionParamRejected(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, media.SDESKeyLen))
	lines := parseCryptoAttrs([]string{"1 AES_CM_128_HMAC_SHA1_80 inline:" + key + " UNENCRYPTED_SRTP"})
	if len(lines) != 0 {
		t.Fatalf("parseCryptoAttrs ignored session param UNENCRYPTED_SRTP: %+v", lines)
	}
}

// audit: P2-TRK-022
// RFC 5124: RTP/SAVPF is a secure profile.
func TestAuditOfferedCryptoSAVPF(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, media.SDESKeyLen))
	body := []byte("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n" +
		"m=audio 4000 RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + key + "\r\n")
	secure, lines := offeredCrypto(body)
	if !secure {
		t.Errorf("offeredCrypto(RTP/SAVPF) secure = false, want true (lines=%d)", len(lines))
	}
}

// audit: P2-TRK-022
// RFC 4566 §5.7: c= may carry an FQDN.
func TestAuditRemoteMediaIPFQDN(t *testing.T) {
	body := []byte("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 media.example.com\r\nt=0 0\r\n" +
		"m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
	if _, err := remoteMediaIP(body); err != nil {
		t.Fatalf("remoteMediaIP rejected an FQDN c= line: %v", err)
	}
}

// audit: P3-TRK-N01 (new in Phase 3)
// RFC 3264 §6 / RFC 6466: an offer may carry an m=image (T.38 fax) section
// next to audio; the answerer declines what it does not relay with port 0.
// The trunk parses with pion/sdp v3.0.19, whose Unmarshal only accepts
// audio|video|text|application|message media, so the whole offer fails to
// parse and the call cannot be placed.
func TestAuditT38ImageSectionAccepted(t *testing.T) {
	body := []byte("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n" +
		"m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n" +
		"m=image 4002 udptl t38\r\n")
	if err := validAudioSDP(body); err != nil {
		t.Fatalf("validAudioSDP rejected an audio+T.38 offer: %v", err)
	}
	if _, err := rewriteSDPCrypto(body, netip.MustParseAddr("192.0.2.10"), 40000, nil); err != nil {
		t.Fatalf("rewriteSDPCrypto rejected an audio+T.38 offer: %v", err)
	}
}
