package sdp

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	pionsdp "github.com/pion/sdp/v3"
)

// Audit tests (docs/audit/REPORT.md). A failing test here is the
// deliverable: it demonstrates a defect. Do not make it pass by editing the
// test; fix the production code instead.

const auditSentinelIP = "203.0.113.77"

func auditBuildFor(t *testing.T, codecs []Codec) Build {
	t.Helper()
	return Build{
		Address: netip.MustParseAddr("10.0.0.1"), Port: 40000,
		Codecs: codecs, SessionID: 1, SessionVersion: 1,
	}
}

// audit: P2-SDP-001
// RFC 3264 §6: the answer's m-lines must be in the offer's order and of the
// offer's media type. A dead audio section followed by a live one must be
// answered with the live audio at index 1, and a video-first offer must get
// m=video at index 0.
func TestAuditMarshalDecliningPreservesOrder(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		liveIndex  int
		wantMedias []string
	}{
		{
			name: "dead audio then live audio",
			body: "v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\n" +
				"m=audio 0 RTP/AVP 0\r\n" +
				"m=audio 4000 RTP/AVP 0\r\n",
			liveIndex:  1,
			wantMedias: []string{"audio", "audio"},
		},
		{
			name: "video then audio",
			body: "v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\n" +
				"m=video 5000 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\n" +
				"m=audio 4000 RTP/AVP 0\r\n",
			liveIndex:  1,
			wantMedias: []string{"video", "audio"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, err := Parse([]byte(tc.body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			out, err := auditBuildFor(t, sess.Audio.Codecs).MarshalDeclining(sess)
			if err != nil {
				t.Fatalf("MarshalDeclining: %v", err)
			}
			var sd pionsdp.SessionDescription
			if err := sd.Unmarshal(out); err != nil {
				t.Fatalf("re-parse: %v\n%s", err, out)
			}
			if len(sd.MediaDescriptions) != len(tc.wantMedias) {
				t.Fatalf("answer has %d m-lines, offer had %d", len(sd.MediaDescriptions), len(tc.wantMedias))
			}
			for i, md := range sd.MediaDescriptions {
				if md.MediaName.Media != tc.wantMedias[i] {
					t.Errorf("m-line %d media = %q, offer had %q (RFC 3264 §6)", i, md.MediaName.Media, tc.wantMedias[i])
				}
				live := md.MediaName.Port.Value != 0
				if live != (i == tc.liveIndex) {
					t.Errorf("m-line %d port = %d; live audio must sit at offer index %d (RFC 3264 §6)", i, md.MediaName.Port.Value, tc.liveIndex)
				}
			}
		})
	}
}

// audit: P2-SDP-003
// Invariant: an emitted body is built from scratch; nothing from the other
// leg's body (in particular no address) may appear in it. The fmtp value is
// free text that crosses legs verbatim.
func TestAuditFmtpDoesNotCarryOtherLegText(t *testing.T) {
	cases := map[string]string{
		"sentinel address in fmtp":  "a=fmtp:0 x=" + auditSentinelIP + "\r\n",
		"lone CR injects a c= line": "a=fmtp:0 x=1\rc=IN IP4 " + auditSentinelIP + " \r\n",
	}
	for name, fmtpLine := range cases {
		t.Run(name, func(t *testing.T) {
			body := "v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\n" +
				"m=audio 4000 RTP/AVP 0\r\n" + fmtpLine
			sess, err := Parse([]byte(body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			out, err := auditBuildFor(t, sess.Audio.Codecs).Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			s := string(out)
			if strings.Contains(s, auditSentinelIP) {
				t.Errorf("emitted body carries the other leg's address %s:\n%q", auditSentinelIP, s)
			}
			if strings.Contains(strings.ReplaceAll(s, "\r\n", ""), "\r") {
				t.Errorf("emitted body contains a bare CR (RFC 4566 §5):\n%q", s)
			}
		})
	}
}

// audit: P2-SDP-004
// RFC 3264 §8.4 / invariant: an address that is unspecified, loopback,
// multicast or link-local must not come out of Parse as a usable media
// destination.
func TestAuditParseRejectsNonUnicastDestination(t *testing.T) {
	for _, addr := range []string{"IP4 0.0.0.0", "IP4 127.0.0.1", "IP4 224.1.1.1", "IP4 169.254.1.1", "IP6 ::1"} {
		t.Run(addr, func(t *testing.T) {
			body := "v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN " + addr + "\r\nt=0 0\r\n" +
				"m=audio 4000 RTP/AVP 0\r\n"
			sess, err := Parse([]byte(body))
			if err != nil {
				return // rejected: acceptable
			}
			a := sess.Audio.Address
			if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
				t.Errorf("Parse returned %s as a media destination", a)
			}
		})
	}
}

// audit: P2-SDP-005
// RFC 3264 §6.1 allows one encoding under several payload types. An answer
// that echoes the offer exactly must not be reported as renumbered.
func TestAuditNegotiateDuplicateKeyNotRenumbered(t *testing.T) {
	list := []Codec{
		{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2},
		{PayloadType: 96, Name: "opus", ClockRate: 48000, Channels: 2, FMTP: "stereo=1"},
		{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1},
	}
	_, err := Negotiate(list, list)
	if errors.Is(err, ErrRenumbered) {
		t.Errorf("identical offer and answer reported as renumbered: %v", err)
	} else if err != nil {
		t.Errorf("Negotiate: %v", err)
	}
}

// audit: P2-SDP-006
// RFC 8122 §5: fingerprint is 2UHEX pairs. Control bytes 0x10-0x19 are not
// hex digits.
func TestAuditFingerprintRejectsControlBytes(t *testing.T) {
	if isHexByte("\x10\x19") {
		t.Errorf("isHexByte accepts control bytes 0x10/0x19")
	}
	parts := make([]string, 32)
	for i := range parts {
		parts[i] = "\x10\x11"
	}
	if _, ok := parseFingerprint("sha-256 " + strings.Join(parts, ":")); ok {
		t.Errorf("parseFingerprint accepted a fingerprint made of control bytes")
	}
}

// audit: P2-SDP-009
// The parseCodecs comment says out-of-range payload types are skipped, not
// fatal; 128-255 are skipped but 256+ fail the whole body.
func TestAuditParseSkipsPayloadTypeAbove255(t *testing.T) {
	body := "v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\n" +
		"m=audio 4000 RTP/AVP 0 300\r\n"
	sess, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse failed on an out-of-range PT the comment says is skipped: %v", err)
	}
	if len(sess.Audio.Codecs) != 1 || sess.Audio.Codecs[0].Name != "PCMU" {
		t.Errorf("codecs = %v, want [PCMU]", sess.Audio.Codecs)
	}
}

// audit: P2-SDP-012
// RFC 5245 §15.4: ice-pwd is 22-256 ice-chars (ufrag 4-256).
func TestAuditICEPwdMinimumLength(t *testing.T) {
	body := strings.Replace(browserOffer, "a=ice-pwd:x9cml/YzichV2+XlhiMu8g", "a=ice-pwd:abcd", 1)
	sess, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if sess.Audio.ICEPwd != "" {
		t.Errorf("a 4-character ice-pwd %q was accepted (RFC 5245 §15.4 requires >= 22)", sess.Audio.ICEPwd)
	}
}

// audit: fuzz (crash hunt)
// Parse, Negotiate and Build must never panic, and whatever Parse accepts
// must build into a body that re-parses with the same section count.
func FuzzAuditParseBuild(f *testing.F) {
	f.Add([]byte(phoneOffer))
	f.Add([]byte(browserOffer))
	f.Add([]byte("v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\nm=audio 4000 RTP/AVP 0 300\r\na=fmtp:0 x=1\rc=IN IP4 1.2.3.4\r\n"))
	f.Add([]byte("v=0\r\no=- 1 1 IN IP6 ::1\r\ns=-\r\nc=IN IP6 ::1\r\nt=0 0\r\nm=video 5000 RTP/AVP 96\r\nm=audio 4000 RTP/AVP 96 101\r\na=rtpmap:96 opus/48000/2\r\na=rtpmap:101 telephone-event/8000\r\n"))
	advertised := netip.MustParseAddr("10.0.0.1")
	f.Fuzz(func(t *testing.T, body []byte) {
		sess, err := Parse(body)
		if err != nil {
			return
		}
		if sess.Audio == nil || len(sess.Audio.Codecs) == 0 || !sess.Audio.Address.IsValid() {
			t.Fatalf("Parse returned an unusable session without error: %+v", sess)
		}
		for _, c := range sess.Audio.Codecs {
			if c.PayloadType > 127 {
				t.Fatalf("PT %d > 127 accepted", c.PayloadType)
			}
		}
		codecs, err := Negotiate(sess.Audio.Codecs, sess.Audio.Codecs)
		if err != nil {
			return
		}
		b := Build{Address: advertised, Port: 40000, Codecs: codecs, SessionID: 1, SessionVersion: 1}
		out, err := b.MarshalDeclining(sess)
		if err != nil {
			return
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("built body does not re-parse: %v\n%q", err, out)
		}
		if again.MediaCount != sess.MediaCount {
			t.Fatalf("section count %d, offer %d", again.MediaCount, sess.MediaCount)
		}
	})
}

// audit: P2-SDP-003 (fuzz property)
// Sentinel leak property: the fuzzer controls every attribute of an offer
// whose connection address and port are sentinels. The body built from it
// must contain neither the sentinel address nor any bare CR.
func FuzzAuditBuildNoSentinelLeak(f *testing.F) {
	f.Add("a=rtpmap:96 opus/48000/2", "a=fmtp:96 minptime=10", "a=sendrecv")
	f.Add("a=rtcp:47111 IN IP4 "+auditSentinelIP, "a=candidate:1 1 UDP 1 "+auditSentinelIP+" 47110 typ host", "a=fmtp:0 x=1")
	advertised := netip.MustParseAddr("10.0.0.1")
	f.Fuzz(func(t *testing.T, a1, a2, a3 string) {
		body := "v=0\r\no=- 1 1 IN IP4 " + auditSentinelIP + "\r\ns=-\r\nc=IN IP4 " + auditSentinelIP +
			"\r\nt=0 0\r\nm=audio 47110 RTP/AVP 0 96\r\n" + a1 + "\r\n" + a2 + "\r\n" + a3 + "\r\n"
		sess, err := Parse([]byte(body))
		if err != nil {
			return
		}
		out, err := Build{Address: advertised, Port: 40000, Codecs: sess.Audio.Codecs, SessionID: 1, SessionVersion: 1}.MarshalDeclining(sess)
		if err != nil {
			return
		}
		s := string(out)
		if strings.Contains(s, auditSentinelIP) || strings.Contains(s, "47110") || strings.Contains(s, "47111") {
			t.Fatalf("built body carries the other leg's sentinel address/port:\n%q", s)
		}
		if strings.Contains(strings.ReplaceAll(s, "\r\n", ""), "\r") {
			t.Fatalf("built body contains a bare CR:\n%q", s)
		}
	})
}
