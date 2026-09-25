package sdp

import (
	"errors"
	"strings"
	"testing"
)

const strictHead = "v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\n"

// audit: P2-SDP-010
// A body whose only audio is declined is an RFC 3264 §6 rejection, told
// apart from a body with no audio at all; both still match ErrNoAudio.
func TestParseDeclinedAudioDistinct(t *testing.T) {
	_, err := Parse([]byte(strictHead + "m=audio 0 RTP/AVP 0\r\n"))
	if !errors.Is(err, ErrAudioDeclined) || !errors.Is(err, ErrNoAudio) {
		t.Errorf("declined audio: err = %v, want ErrAudioDeclined wrapping ErrNoAudio", err)
	}
	_, err = Parse([]byte(strictHead + "m=video 5000 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\n"))
	if !errors.Is(err, ErrNoAudio) || errors.Is(err, ErrAudioDeclined) {
		t.Errorf("no audio: err = %v, want ErrNoAudio only", err)
	}
}

// audit: P2-SDP-011
// a=rtcp-mux is parsed so a caller can tell whether an answer may carry it.
func TestParseRTCPMux(t *testing.T) {
	sess, err := Parse([]byte(browserOffer))
	if err != nil {
		t.Fatal(err)
	}
	if !sess.Audio.RTCPMux {
		t.Error("a=rtcp-mux in the offer not reported")
	}
	sess, err = Parse([]byte(strings.Replace(browserOffer, "a=rtcp-mux\r\n", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if sess.Audio.RTCPMux {
		t.Error("RTCPMux reported for an offer without a=rtcp-mux")
	}
}

// audit: P2-SDP-008
// An rtpmap encoding name outside letters, digits, '-', '_', '.' makes the
// codec unusable, so Describe can rely on it.
func TestParseRejectsOddEncodingNames(t *testing.T) {
	for _, name := range []string{"op us", "op\"us", "opus\r", "op;us"} {
		body := strictHead + "m=audio 4000 RTP/AVP 0 96\r\na=rtpmap:96 " + name + "/48000/2\r\n"
		sess, err := Parse([]byte(body))
		if err != nil {
			continue
		}
		for _, c := range sess.Audio.Codecs {
			if c.PayloadType == 96 {
				t.Errorf("encoding name %q accepted as %q", name, c.Name)
			}
		}
	}
	sess, err := Parse([]byte(strictHead + "m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n"))
	if err != nil || sess.Audio.Codecs[0].Name != "AMR-WB" {
		t.Errorf("AMR-WB: %v %v", sess, err)
	}
}

// audit: P2-SDP-009
// A non-numeric format still fails an RTP audio section.
func TestParseNonNumericFormatFails(t *testing.T) {
	if _, err := Parse([]byte(strictHead + "m=audio 4000 RTP/AVP 0 abc\r\n")); err == nil {
		t.Error("non-numeric payload type accepted")
	}
}

// audit: P2-SDP-012
// ice-ufrag keeps its 4-character minimum while ice-pwd needs 22.
func TestICEUfragMinimumUnchanged(t *testing.T) {
	sess, err := Parse([]byte(browserOffer))
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.Audio.ICEUfrag) != 4 || sess.Audio.ICEPwd == "" {
		t.Errorf("ufrag %q / pwd %q", sess.Audio.ICEUfrag, sess.Audio.ICEPwd)
	}
}
