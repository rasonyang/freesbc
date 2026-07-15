package sig

import (
	"net/netip"
	"strings"
	"testing"
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
