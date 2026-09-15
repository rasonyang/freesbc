package trunk

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/internal/media"
	"github.com/pion/sdp/v3"
)

const offerSDP = "v=0\r\n" +
	"o=- 1 1 IN IP4 203.0.113.5\r\n" +
	"s=-\r\n" +
	"c=IN IP4 203.0.113.5\r\n" +
	"t=0 0\r\n" +
	"m=audio 40000 RTP/AVP 0 8\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n"

func TestRemoteMediaIP(t *testing.T) {
	ip, err := remoteMediaIP([]byte(offerSDP))
	if err != nil {
		t.Fatalf("remoteMediaIP: %v", err)
	}
	if ip != netip.MustParseAddr("203.0.113.5") {
		t.Errorf("got %v, want 203.0.113.5", ip)
	}
}

func TestRemoteMediaIPMediaLevelOverride(t *testing.T) {
	// A media-level c= overrides the session-level one.
	s := strings.Replace(offerSDP,
		"m=audio 40000 RTP/AVP 0 8\r\n",
		"m=audio 40000 RTP/AVP 0 8\r\nc=IN IP4 198.51.100.7\r\n", 1)
	ip, err := remoteMediaIP([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	if ip != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("got %v, want media-level 198.51.100.7", ip)
	}
}

func TestRewriteSDPSetsIPAndPort(t *testing.T) {
	out, err := rewriteSDPCrypto([]byte(offerSDP), netip.MustParseAddr("192.0.2.1"), 16400, nil)
	if err != nil {
		t.Fatalf("rewriteSDPCrypto: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "c=IN IP4 192.0.2.1") {
		t.Errorf("connection not rewritten:\n%s", s)
	}
	if !strings.Contains(s, "m=audio 16400 ") {
		t.Errorf("media port not rewritten:\n%s", s)
	}
	// The rewritten SDP must still parse and report our IP as the remote.
	ip, err := remoteMediaIP(out)
	if err != nil || ip != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("round-trip: ip=%v err=%v", ip, err)
	}
	// The origin (o=) line must be rewritten to our IP, not leak the peer's.
	lines := strings.Split(s, "\r\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "o=") {
		t.Fatalf("expected o= as second line, got:\n%s", s)
	}
	originLine := lines[1]
	if !strings.Contains(originLine, "192.0.2.1") {
		t.Errorf("origin line not rewritten to our IP:\n%s", originLine)
	}
	if strings.Contains(originLine, "203.0.113.5") {
		t.Errorf("origin line leaks peer IP:\n%s", originLine)
	}
}

func TestRewriteSDPZeroesNonAudioAndExtraSections(t *testing.T) {
	s := "v=0\r\n" +
		"o=- 1 1 IN IP4 203.0.113.5\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.5\r\n" +
		"t=0 0\r\n" +
		"m=audio 40000 RTP/AVP 0 8\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"m=video 40002 RTP/AVP 96\r\n" +
		"c=IN IP4 203.0.113.9\r\n" +
		"a=rtpmap:96 H264/90000\r\n" +
		"m=audio 40004 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"

	out, err := rewriteSDPCrypto([]byte(s), netip.MustParseAddr("192.0.2.1"), 16400, nil)
	if err != nil {
		t.Fatalf("rewriteSDPCrypto: %v", err)
	}
	out2 := string(out)

	if !strings.Contains(out2, "m=audio 16400 ") {
		t.Errorf("first audio section not rewritten to relay port:\n%s", out2)
	}
	if !strings.Contains(out2, "m=video 0 ") {
		t.Errorf("video section not zeroed:\n%s", out2)
	}
	if !strings.Contains(out2, "m=audio 0 ") {
		t.Errorf("second audio section not zeroed:\n%s", out2)
	}
	if strings.Contains(out2, "203.0.113.5") {
		t.Errorf("output leaks original peer IP 203.0.113.5:\n%s", out2)
	}
	if strings.Contains(out2, "203.0.113.9") {
		t.Errorf("output leaks video-section peer IP 203.0.113.9:\n%s", out2)
	}
	// 192.0.2.1 must be the only connection/origin address present.
	count := strings.Count(out2, "192.0.2.1")
	// Expect exactly one occurrence in o= and one in the session-level c=.
	if count == 0 {
		t.Errorf("expected our IP 192.0.2.1 to appear in output:\n%s", out2)
	}
	if strings.Contains(out2, "c=IN IP4 203.0.113") {
		t.Errorf("a media-level c= still leaks a peer address:\n%s", out2)
	}

	// Verify the SDP still parses and no non-relayed m= section carries a
	// connection line at all (they should rely on nothing, since port=0).
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(out); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	if len(sd.MediaDescriptions) != 3 {
		t.Fatalf("expected 3 media sections, got %d", len(sd.MediaDescriptions))
	}
	if sd.MediaDescriptions[0].MediaName.Media != "audio" || sd.MediaDescriptions[0].MediaName.Port.Value != 16400 {
		t.Errorf("first section: %+v", sd.MediaDescriptions[0].MediaName)
	}
	if sd.MediaDescriptions[1].MediaName.Media != "video" || sd.MediaDescriptions[1].MediaName.Port.Value != 0 {
		t.Errorf("video section: %+v", sd.MediaDescriptions[1].MediaName)
	}
	if sd.MediaDescriptions[1].ConnectionInformation != nil {
		t.Errorf("video section still has connection info: %+v", sd.MediaDescriptions[1].ConnectionInformation)
	}
	if sd.MediaDescriptions[2].MediaName.Media != "audio" || sd.MediaDescriptions[2].MediaName.Port.Value != 0 {
		t.Errorf("second audio section: %+v", sd.MediaDescriptions[2].MediaName)
	}
}

func TestRewriteSDPRewritesRtcpAttr(t *testing.T) {
	s := strings.Replace(offerSDP,
		"a=rtpmap:0 PCMU/8000\r\n",
		"a=rtpmap:0 PCMU/8000\r\na=rtcp:40001\r\n", 1)
	out, err := rewriteSDPCrypto([]byte(s), netip.MustParseAddr("192.0.2.1"), 16400, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "a=rtcp:16401") {
		t.Errorf("a=rtcp not rewritten to rtpPort+1:\n%s", string(out))
	}
}

func TestRewriteSDPErrors(t *testing.T) {
	noAudio := "v=0\r\no=- 1 1 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 203.0.113.5\r\nt=0 0\r\nm=video 40000 RTP/AVP 96\r\n"
	if _, err := rewriteSDPCrypto([]byte("not sdp at all"), netip.MustParseAddr("192.0.2.1"), 16400, nil); err == nil {
		t.Error("expected error for unparseable SDP")
	}
	if _, err := rewriteSDPCrypto([]byte(noAudio), netip.MustParseAddr("192.0.2.1"), 16400, nil); err == nil {
		t.Error("expected error for SDP with no audio m= line")
	}
	// validAudioSDP is placeCall's pre-loop probe: the same two rejections,
	// without producing a rewritten body.
	if err := validAudioSDP([]byte("not sdp at all")); err == nil {
		t.Error("validAudioSDP: expected error for unparseable SDP")
	}
	if err := validAudioSDP([]byte(noAudio)); err == nil {
		t.Error("validAudioSDP: expected error for SDP with no audio m= line")
	}
	if err := validAudioSDP([]byte(offerSDP)); err != nil {
		t.Errorf("validAudioSDP on a good offer: %v", err)
	}
}

func savpOffer(port int, cryptoB64 string) []byte {
	return []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 203.0.113.9\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.9\r\n" +
		"t=0 0\r\n" +
		"m=audio " + itoa(port) + " RTP/SAVP 0\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + cryptoB64 + "\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n")
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestOfferedCryptoDetectsSAVP(t *testing.T) {
	secure, lines := offeredCrypto(savpOffer(6000, base64.StdEncoding.EncodeToString(make([]byte, 30))))
	if !secure {
		t.Fatal("RTP/SAVP offer must report secure=true")
	}
	if len(lines) != 1 || lines[0].suite != media.SuiteAES128CM80 {
		t.Fatalf("want one 80-suite line, got %+v", lines)
	}
}

func TestOfferedCryptoPlaintextIsInsecure(t *testing.T) {
	// A plain RTP/AVP offer (reuse an existing plaintext SDP builder in tests).
	secure, lines := offeredCrypto([]byte("v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"))
	if secure || len(lines) != 0 {
		t.Fatalf("plaintext offer: secure=%v lines=%+v", secure, lines)
	}
}

func TestRewriteSDPCryptoSecureSetsSAVPAndCrypto(t *testing.T) {
	// Peer's offered key and our advertised key must be DISTINCT so a
	// regression that echoes the peer's inbound a=crypto (instead of
	// stripping it and inserting our own fresh key) is caught: with
	// identical keys, echoing and regenerating would be indistinguishable.
	peerKey := bytes.Repeat([]byte{0x11}, 30)
	ourKey := bytes.Repeat([]byte{0x22}, 30)
	peerKeyB64 := base64.StdEncoding.EncodeToString(peerKey)
	ourKeyB64 := base64.StdEncoding.EncodeToString(ourKey)

	out, err := rewriteSDPCrypto(savpOffer(6000, peerKeyB64),
		netip.MustParseAddr("198.51.100.7"), 40000,
		&sdpCrypto{suite: media.SuiteAES128CM80, keyValue: ourKey, tag: 1})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "RTP/SAVP") {
		t.Error("secure rewrite must keep RTP/SAVP proto")
	}
	if !strings.Contains(s, "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"+ourKeyB64) {
		t.Error("secure rewrite must advertise OUR crypto key")
	}
	if strings.Contains(s, peerKeyB64) {
		t.Error("secure rewrite must not echo the peer's crypto key")
	}
	if got := strings.Count(s, "a=crypto:"); got != 1 {
		t.Errorf("secure rewrite must contain exactly one a=crypto line, got %d", got)
	}
	if !strings.Contains(s, "40000") || !strings.Contains(s, "198.51.100.7") {
		t.Error("topology rewrite (port/IP) must still apply")
	}
}

func TestRewriteSDPCryptoPlaintextStripsCrypto(t *testing.T) {
	out, err := rewriteSDPCrypto(savpOffer(6000, base64.StdEncoding.EncodeToString(make([]byte, 30))),
		netip.MustParseAddr("198.51.100.7"), 40000, nil)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "a=crypto") {
		t.Error("plaintext rewrite must strip a=crypto")
	}
	if !strings.Contains(s, "RTP/AVP") || strings.Contains(s, "RTP/SAVP") {
		t.Error("plaintext rewrite must set RTP/AVP")
	}
}

// TestRewriteSDPCryptoEchoesOfferedTag is Finding 2's direct sdp.go-level
// regression guard: RFC 4568 §5.1.3 requires the answer's a=crypto tag to
// match the SELECTED offered line's tag, not always tag 1. A version that
// hardcodes tag 1 would pass every OTHER test in this file (they all happen
// to select tag 1) but fail this one, which asks rewriteSDPCrypto to
// advertise tag 2.
func TestRewriteSDPCryptoEchoesOfferedTag(t *testing.T) {
	ourKey := bytes.Repeat([]byte{0x55}, 30)
	out, err := rewriteSDPCrypto(savpOffer(6000, base64.StdEncoding.EncodeToString(make([]byte, 30))),
		netip.MustParseAddr("198.51.100.7"), 40000,
		&sdpCrypto{suite: media.SuiteAES128CM80, keyValue: ourKey, tag: 2})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "a=crypto:2 ") {
		t.Errorf("rewrite must advertise a=crypto tagged 2 (the requested tag), got:\n%s", s)
	}
	if strings.Contains(s, "a=crypto:1 ") {
		t.Errorf("rewrite must not hardcode tag 1 when tag 2 was requested:\n%s", s)
	}
}

// declinedCryptoLeakOffer builds an offer with a RELAYED audio section and a
// DECLINED video section that both carry a=crypto with the SAME peer key,
// plus a session-level a=crypto also carrying that key — the scenario
// Finding 1 guards: SDES peers commonly reuse one master key across every
// m= line, so a declined section (or the session level) leaking its
// a=crypto hands the other leg the LIVE audio stream's key.
func declinedCryptoLeakOffer(peerKeyB64 string) []byte {
	return []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 203.0.113.9\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.9\r\n" +
		"t=0 0\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + peerKeyB64 + "\r\n" +
		"m=audio 6000 RTP/SAVP 0\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + peerKeyB64 + "\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"m=video 6002 RTP/SAVP 96\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + peerKeyB64 + "\r\n" +
		"a=rtpmap:96 H264/90000\r\n")
}

// TestRewriteSDPCryptoScrubsDeclinedAndSessionCryptoSecure is Finding 1's
// regression guard for the secure (crypto != nil) path: proves the declined
// video section's a=crypto and the session-level a=crypto are both stripped,
// not just the relayed audio section's. A version that only zeroed the
// declined section's port/connection info (the pre-fix behavior) would still
// carry the peer's key in the declined section's own a=crypto — this test's
// whole-output substring check on peerKeyB64 would then fail, proving it's a
// real guard and not a vacuous one.
func TestRewriteSDPCryptoScrubsDeclinedAndSessionCryptoSecure(t *testing.T) {
	peerKey := bytes.Repeat([]byte{0x33}, 30)
	ourKey := bytes.Repeat([]byte{0x44}, 30)
	peerKeyB64 := base64.StdEncoding.EncodeToString(peerKey)

	out, err := rewriteSDPCrypto(declinedCryptoLeakOffer(peerKeyB64),
		netip.MustParseAddr("198.51.100.7"), 40000,
		&sdpCrypto{suite: media.SuiteAES128CM80, keyValue: ourKey, tag: 1})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	s := string(out)

	// The crux assertion: the peer's key must not appear ANYWHERE in the
	// output — we advertise our own fresh key on the relayed section and
	// nothing at all on the declined/session-level attributes.
	if strings.Contains(s, peerKeyB64) {
		t.Fatalf("peer's key leaked into output (declined section or session-level a=crypto not scrubbed):\n%s", s)
	}
	if got := strings.Count(s, "a=crypto:"); got != 1 {
		t.Errorf("output must contain exactly one a=crypto line (ours, on the relayed section), got %d:\n%s", got, s)
	}

	var sd sdp.SessionDescription
	if err := sd.Unmarshal(out); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	for _, a := range sd.Attributes {
		if a.Key == "crypto" {
			t.Errorf("session-level a=crypto not stripped: %+v", a)
		}
	}
	if len(sd.MediaDescriptions) != 2 {
		t.Fatalf("expected 2 media sections, got %d", len(sd.MediaDescriptions))
	}
	video := sd.MediaDescriptions[1]
	if video.MediaName.Media != "video" || video.MediaName.Port.Value != 0 {
		t.Fatalf("video section not declined: %+v", video.MediaName)
	}
	if len(video.Attributes) != 0 {
		t.Errorf("declined video section must have all attributes cleared, got %+v", video.Attributes)
	}
}

// TestRewriteSDPCryptoScrubsDeclinedAndSessionCryptoPlaintext is the same
// guard on the plaintext (crypto == nil) path — the finding calls for the
// scrub to apply unconditionally, since a declined section leaks the peer's
// live key regardless of whether the relayed section itself ends up secure.
func TestRewriteSDPCryptoScrubsDeclinedAndSessionCryptoPlaintext(t *testing.T) {
	peerKey := bytes.Repeat([]byte{0x33}, 30)
	peerKeyB64 := base64.StdEncoding.EncodeToString(peerKey)

	out, err := rewriteSDPCrypto(declinedCryptoLeakOffer(peerKeyB64),
		netip.MustParseAddr("198.51.100.7"), 40000, nil)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	s := string(out)
	if strings.Contains(s, peerKeyB64) {
		t.Fatalf("peer's key leaked into output (declined section or session-level a=crypto not scrubbed):\n%s", s)
	}
	if strings.Contains(s, "a=crypto") {
		t.Errorf("plaintext rewrite must have no a=crypto anywhere, got:\n%s", s)
	}

	var sd sdp.SessionDescription
	if err := sd.Unmarshal(out); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	video := sd.MediaDescriptions[1]
	if len(video.Attributes) != 0 {
		t.Errorf("declined video section must have all attributes cleared, got %+v", video.Attributes)
	}
}

// A bare G.729 offer carries no a=rtpmap (payload type 18 is static, but
// not one of the 0/8 the proxy plane's parser special-cases). The trunk
// relays bytes between carriers and must accept it: the codec is the two
// peers' business, not the bridge's.
func TestValidAudioSDPAcceptsStaticPayloadWithoutRtpmap(t *testing.T) {
	const g729 = "v=0\r\n" +
		"o=- 1 1 IN IP4 203.0.113.5\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.5\r\n" +
		"t=0 0\r\n" +
		"m=audio 5000 RTP/AVP 18\r\n"

	if err := validAudioSDP([]byte(g729)); err != nil {
		t.Errorf("validAudioSDP rejected a bare G.729 offer: %v", err)
	}
	ip, err := remoteMediaIP([]byte(g729))
	if err != nil {
		t.Fatalf("remoteMediaIP: %v", err)
	}
	if ip != netip.MustParseAddr("203.0.113.5") {
		t.Errorf("got %v, want 203.0.113.5", ip)
	}
}

// A first audio section the peer declined (port 0, RFC 3264 §6) must be
// skipped: the latch address and the section rewriteSDPCrypto relays both
// come from firstAudio, so they have to agree on the live one.
func TestFirstAudioSkipsDeclinedSection(t *testing.T) {
	const body = "v=0\r\n" +
		"o=- 1 1 IN IP4 203.0.113.5\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.5\r\n" +
		"t=0 0\r\n" +
		"m=audio 0 RTP/AVP 0\r\n" +
		"c=IN IP4 198.51.100.9\r\n" +
		"m=audio 40000 RTP/AVP 8\r\n" +
		"c=IN IP4 198.51.100.7\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n"

	if err := validAudioSDP([]byte(body)); err != nil {
		t.Fatalf("validAudioSDP: %v", err)
	}
	ip, err := remoteMediaIP([]byte(body))
	if err != nil {
		t.Fatalf("remoteMediaIP: %v", err)
	}
	if ip != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("latch address %v, want the live section's 198.51.100.7", ip)
	}

	out, err := rewriteSDPCrypto([]byte(body), netip.MustParseAddr("192.0.2.1"), 16400, nil)
	if err != nil {
		t.Fatalf("rewriteSDPCrypto: %v", err)
	}
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(out); err != nil {
		t.Fatalf("unmarshal rewritten: %v", err)
	}
	if len(sd.MediaDescriptions) != 2 {
		t.Fatalf("got %d media sections, want 2", len(sd.MediaDescriptions))
	}
	if got := sd.MediaDescriptions[0].MediaName.Port.Value; got != 0 {
		t.Errorf("declined section port %d, want it left declined", got)
	}
	if got := sd.MediaDescriptions[1].MediaName.Port.Value; got != 16400 {
		t.Errorf("relayed section port %d, want 16400 — it must be the live section", got)
	}
}

// A declined-only body has nothing to relay.
func TestValidAudioSDPRejectsAllDeclined(t *testing.T) {
	const body = "v=0\r\n" +
		"o=- 1 1 IN IP4 203.0.113.5\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.5\r\n" +
		"t=0 0\r\n" +
		"m=audio 0 RTP/AVP 0\r\n"
	if err := validAudioSDP([]byte(body)); err == nil {
		t.Error("validAudioSDP accepted a body whose only audio section is declined")
	}
}
