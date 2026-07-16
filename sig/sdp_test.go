package sig

import (
	"net/netip"
	"strings"
	"testing"

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
	out, err := rewriteSDP([]byte(offerSDP), netip.MustParseAddr("192.0.2.1"), 16400)
	if err != nil {
		t.Fatalf("rewriteSDP: %v", err)
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

	out, err := rewriteSDP([]byte(s), netip.MustParseAddr("192.0.2.1"), 16400)
	if err != nil {
		t.Fatalf("rewriteSDP: %v", err)
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
	out, err := rewriteSDP([]byte(s), netip.MustParseAddr("192.0.2.1"), 16400)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "a=rtcp:16401") {
		t.Errorf("a=rtcp not rewritten to rtpPort+1:\n%s", string(out))
	}
}

func TestRewriteSDPErrors(t *testing.T) {
	if _, err := rewriteSDP([]byte("not sdp at all"), netip.MustParseAddr("192.0.2.1"), 16400); err == nil {
		t.Error("expected error for unparseable SDP")
	}
	noAudio := "v=0\r\no=- 1 1 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 203.0.113.5\r\nt=0 0\r\nm=video 40000 RTP/AVP 96\r\n"
	if _, err := rewriteSDP([]byte(noAudio), netip.MustParseAddr("192.0.2.1"), 16400); err == nil {
		t.Error("expected error for SDP with no audio m= line")
	}
}
