package sdp

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// audit: P2-SDP-003
// The allowlist must keep what two endpoints legitimately negotiate while
// dropping everything else.
func TestCanonicalFMTP(t *testing.T) {
	cases := []struct {
		name, codec, raw, want string
	}{
		{"opus kept", "opus", "minptime=10;useinbandfec=1", "minptime=10;useinbandfec=1"},
		{"opus spaces and case", "OPUS", " MinPTime = 10 ; stereo=1", "minptime=10;stereo=1"},
		{"opus unknown key dropped", "opus", "minptime=10;x=203.0.113.77", "minptime=10"},
		{"opus bad value dropped", "opus", "useinbandfec=yes;maxplaybackrate=16000", "maxplaybackrate=16000"},
		{"opus duplicate key keeps first", "opus", "stereo=1;stereo=0", "stereo=1"},
		{"opus bare CR", "opus", "minptime=10\rc=IN IP4 203.0.113.77", ""},
		{"telephone-event", "telephone-event", "0-15", "0-15"},
		{"telephone-event list", "telephone-event", "0-11,16, 66", "0-11,16,66"},
		{"telephone-event noise", "telephone-event", "0-16;x=10.91.0.5;p=59914", "0-16"},
		{"telephone-event out of range", "telephone-event", "0-300", ""},
		{"telephone-event reversed", "telephone-event", "15-0", ""},
		{"PCMU has none", "PCMU", "x=1", ""},
		{"unknown codec", "foo", "a=1", ""},
		{"g729", "G729", "annexb=NO", "annexb=no"},
		{"amr mode-set", "AMR", "octet-align=1; mode-set=0,2,7", "octet-align=1;mode-set=0,2,7"},
		{"amr mode-set out of range", "AMR", "mode-set=0,9", ""},
		{"too long", "opus", strings.Repeat("a", maxFMTP+1), ""},
	}
	for _, tc := range cases {
		if got := canonicalFMTP(tc.codec, tc.raw); got != tc.want {
			t.Errorf("%s: canonicalFMTP(%q, %q) = %q, want %q", tc.name, tc.codec, tc.raw, got, tc.want)
		}
	}
}

// audit: P2-SDP-003
// Build filters a caller-supplied Codec.FMTP too, not only Parse output.
func TestBuildFiltersCallerFMTP(t *testing.T) {
	b := Build{
		Address: netip.MustParseAddr("10.0.0.1"), Port: 40000, SessionID: 1, SessionVersion: 1,
		Codecs: []Codec{
			{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2, FMTP: "useinbandfec=1;x=203.0.113.77"},
			{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1, FMTP: "x=1\rc=IN IP4 203.0.113.77"},
		},
	}
	out, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "203.0.113.77") || !strings.Contains(s, "a=fmtp:111 useinbandfec=1\r\n") || strings.Contains(s, "a=fmtp:0") {
		t.Errorf("fmtp not filtered at build:\n%q", s)
	}
}

// audit: P2-SDP-005
// A real renumbering is still caught when the offer carries duplicates, and
// an answer that picks the second of two offered numbers is not.
func TestNegotiateDuplicateKeys(t *testing.T) {
	opus111 := Codec{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2}
	opus96 := Codec{PayloadType: 96, Name: "opus", ClockRate: 48000, Channels: 2, FMTP: "stereo=1"}
	pcmu := Codec{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1}
	offer := []Codec{opus111, opus96, pcmu}

	got, err := Negotiate(offer, []Codec{opus96})
	if err != nil || len(got) != 1 || got[0].PayloadType != 96 {
		t.Errorf("answer on the second offered number: got %v, %v", got, err)
	}
	moved := opus111
	moved.PayloadType = 120
	if _, err := Negotiate(offer, []Codec{moved, pcmu}); !errors.Is(err, ErrRenumbered) {
		t.Errorf("opus answered on 120, offered on 111/96: err = %v, want ErrRenumbered", err)
	}
	if _, err := Negotiate([]Codec{opus111}, []Codec{{PayloadType: 111, Name: "PCMU", ClockRate: 8000}}); !errors.Is(err, ErrNoCommonCodec) {
		t.Errorf("PT reused for another encoding: err = %v, want ErrNoCommonCodec", err)
	}
}

// audit: P2-SDP-001
// Declined sections echo the offer's media and a vetted transport; an
// unlisted transport is answered as RTP/AVP rather than echoed.
func TestMarshalDecliningEchoesSections(t *testing.T) {
	body := "v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"m=audio 4000 RTP/AVP 0\r\n" +
		"m=video 5000 TCP/RTP/AVP 96\r\n" +
		"m=text 6000 RTP/AVP 98\r\n"
	sess, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if sess.AudioIndex != 1 || len(sess.Sections) != 4 {
		t.Fatalf("AudioIndex %d, %d sections", sess.AudioIndex, len(sess.Sections))
	}
	out, err := auditBuildFor(t, sess.Audio.Codecs).MarshalDeclining(sess)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n",
		"m=audio 40000 RTP/AVP 0\r\n",
		"m=video 0 RTP/AVP 0\r\n",
		"m=text 0 RTP/AVP 0\r\n",
	}
	s := string(out)
	last := -1
	for _, w := range want {
		i := strings.Index(s, w)
		if i <= last {
			t.Fatalf("missing or out of order %q in:\n%s", w, s)
		}
		last = i
	}
	if strings.Contains(s, "TCP/RTP/AVP") {
		t.Errorf("unlisted transport echoed:\n%s", s)
	}
}
