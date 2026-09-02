package sdp

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// A plain SIP hardphone offer: static payload types, no rtpmap for PCMU/
// PCMA, an explicit telephone-event, session-level c=.
const phoneOffer = "v=0\r\n" +
	"o=- 1 1 IN IP4 198.51.100.9\r\n" +
	"s=-\r\n" +
	"c=IN IP4 198.51.100.9\r\n" +
	"t=0 0\r\n" +
	"m=audio 40000 RTP/AVP 0 8 101\r\n" +
	"a=rtpmap:101 telephone-event/8000\r\n" +
	"a=fmtp:101 0-16\r\n" +
	"a=sendrecv\r\n"

// A browser (sip.js) offer: DTLS-SRTP, ICE, rtcp-mux, opus first.
const browserOffer = "v=0\r\n" +
	"o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" +
	"s=-\r\n" +
	"t=0 0\r\n" +
	"m=audio 51234 UDP/TLS/RTP/SAVPF 111 0 8 110\r\n" +
	"c=IN IP4 192.168.1.44\r\n" +
	"a=rtcp:51235 IN IP4 192.168.1.44\r\n" +
	"a=ice-ufrag:F7gI\r\n" +
	"a=ice-pwd:x9cml/YzichV2+XlhiMu8g\r\n" +
	"a=candidate:1 1 UDP 2130706431 192.168.1.44 51234 typ host\r\n" +
	"a=candidate:2 1 UDP 1694498815 203.0.113.99 51234 typ srflx raddr 192.168.1.44 rport 51234\r\n" +
	"a=fingerprint:sha-256 6B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08\r\n" +
	"a=setup:actpass\r\n" +
	"a=mid:0\r\n" +
	"a=rtcp-mux\r\n" +
	"a=rtpmap:111 opus/48000/2\r\n" +
	"a=fmtp:111 minptime=10;useinbandfec=1\r\n" +
	"a=rtpmap:110 telephone-event/48000\r\n" +
	"a=sendrecv\r\n"

func TestParsePhoneOffer(t *testing.T) {
	s, err := Parse([]byte(phoneOffer))
	if err != nil {
		t.Fatal(err)
	}
	a := s.Audio
	if a.Port != 40000 {
		t.Errorf("port = %d", a.Port)
	}
	if a.Address != netip.MustParseAddr("198.51.100.9") {
		t.Errorf("address = %v", a.Address)
	}
	if a.Direction != SendRecv {
		t.Errorf("direction = %v", a.Direction)
	}
	if a.Secure() || a.WebRTC() {
		t.Error("plain RTP offer classified as secure/webrtc")
	}
	want := []Codec{
		{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1},
		{PayloadType: 8, Name: "PCMA", ClockRate: 8000, Channels: 1},
		{PayloadType: 101, Name: "telephone-event", ClockRate: 8000, Channels: 1, FMTP: "0-16"},
	}
	if len(a.Codecs) != len(want) {
		t.Fatalf("codecs = %v", Describe(a.Codecs))
	}
	for i, c := range a.Codecs {
		if c != want[i] {
			t.Errorf("codec[%d] = %+v, want %+v", i, c, want[i])
		}
	}
}

func TestParseBrowserOffer(t *testing.T) {
	s, err := Parse([]byte(browserOffer))
	if err != nil {
		t.Fatal(err)
	}
	a := s.Audio
	if !a.WebRTC() {
		t.Fatal("browser offer not classified as WebRTC")
	}
	if !a.Secure() {
		t.Error("SAVPF not classified as secure")
	}
	if !a.RTCPMux {
		t.Error("rtcp-mux not parsed")
	}
	if a.RTCPPort != 51235 {
		t.Errorf("a=rtcp port = %d", a.RTCPPort)
	}
	if a.ICEUfrag != "F7gI" || a.ICEPwd != "x9cml/YzichV2+XlhiMu8g" {
		t.Errorf("ice credentials = %q/%q", a.ICEUfrag, a.ICEPwd)
	}
	if a.Setup != "actpass" {
		t.Errorf("setup = %q", a.Setup)
	}
	if a.Fingerprint == nil || a.Fingerprint.Hash != "sha-256" {
		t.Fatalf("fingerprint = %+v", a.Fingerprint)
	}
	if len(a.Candidates) != 2 {
		t.Errorf("candidates = %d", len(a.Candidates))
	}
	// Media-level c= must win over the (absent) session-level one.
	if a.Address != netip.MustParseAddr("192.168.1.44") {
		t.Errorf("address = %v", a.Address)
	}
	if a.Codecs[0].Name != "opus" || a.Codecs[0].PayloadType != 111 || a.Codecs[0].Channels != 2 {
		t.Errorf("first codec = %+v", a.Codecs[0])
	}
	if a.Codecs[0].FMTP != "minptime=10;useinbandfec=1" {
		t.Errorf("fmtp = %q", a.Codecs[0].FMTP)
	}
}

func TestParseRejections(t *testing.T) {
	tests := []struct {
		name string
		body string
		want error
	}{
		{"empty", "", nil},
		{"oversize", "v=0\r\n" + strings.Repeat("a=x:y\r\n", 4000), ErrTooLarge},
		{"video only", "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\nm=video 5000 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\n", ErrNoAudio},
		{"declined audio only", "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n", ErrNoAudio},
		{"no connection", "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n", ErrNoAddress},
		{"hostname connection", "v=0\r\no=- 1 1 IN IP4 host.example\r\ns=-\r\nc=IN IP4 host.example\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n", ErrNoAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.body))
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// A dynamic payload type with no rtpmap cannot be identified and must be
// dropped rather than guessed at.
func TestParseDropsUndescribedDynamicPT(t *testing.T) {
	body := "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\n" +
		"m=audio 5000 RTP/AVP 96 0\r\n"
	s, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Audio.Codecs) != 1 || s.Audio.Codecs[0].PayloadType != 0 {
		t.Fatalf("codecs = %v", Describe(s.Audio.Codecs))
	}
}

// Header-injection and junk hardening on the attributes the proxy echoes.
func TestParseSanitizesHostileAttributes(t *testing.T) {
	body := "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\n" +
		"m=audio 5000 UDP/TLS/RTP/SAVPF 0\r\n" +
		"a=ice-ufrag:bad ufrag with spaces\r\n" +
		"a=ice-pwd:ab\r\n" +
		"a=fingerprint:sha-1 AB:CD\r\n" +
		"a=setup:bogus\r\n" +
		"a=candidate:not a candidate\r\n"
	s, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	a := s.Audio
	if a.ICEUfrag != "" {
		t.Errorf("hostile ufrag kept: %q", a.ICEUfrag)
	}
	if a.ICEPwd != "" {
		t.Errorf("too-short pwd kept: %q", a.ICEPwd)
	}
	if a.Fingerprint != nil {
		t.Errorf("sha-1 fingerprint accepted: %v", a.Fingerprint)
	}
	if a.Setup != "" {
		t.Errorf("bogus setup kept: %q", a.Setup)
	}
	if len(a.Candidates) != 0 {
		t.Errorf("malformed candidate kept: %v", a.Candidates)
	}
	// ...and with no fingerprint/ICE it must not be treated as WebRTC.
	if a.WebRTC() {
		t.Error("classified as WebRTC without valid ICE/fingerprint")
	}
}

func TestFilterAndIntersect(t *testing.T) {
	offer, err := Parse([]byte(browserOffer))
	if err != nil {
		t.Fatal(err)
	}
	filtered := Filter(offer.Audio.Codecs)
	if len(filtered) != 4 {
		t.Fatalf("filtered = %v", Describe(filtered))
	}

	// FreeSWITCH answers with PCMU + DTMF only, narrowing the fmtp.
	answer := []Codec{
		{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1},
		{PayloadType: 110, Name: "telephone-event", ClockRate: 48000, Channels: 1, FMTP: "0-15"},
	}
	got, err := Intersect(filtered, answer)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("intersect = %v", Describe(got))
	}
	// Offer order: PCMU (pt 0) came before telephone-event in the offer.
	if got[0].PayloadType != 0 || got[1].PayloadType != 110 {
		t.Errorf("order/numbers wrong: %v", Describe(got))
	}
	// The answerer's fmtp is the one that must reach the offerer.
	if got[1].FMTP != "0-15" {
		t.Errorf("fmtp = %q, want the answerer's 0-15", got[1].FMTP)
	}
}

func TestIntersectNoCommonCodec(t *testing.T) {
	a := []Codec{{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2}}
	b := []Codec{{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1}}
	if _, err := Intersect(a, b); !errors.Is(err, ErrNoCommonCodec) {
		t.Fatalf("err = %v", err)
	}
}

// An intersection that leaves only DTMF is not a usable call.
func TestIntersectDTMFOnlyRejected(t *testing.T) {
	a := []Codec{
		{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1},
		{PayloadType: 101, Name: "telephone-event", ClockRate: 8000, Channels: 1},
	}
	b := []Codec{{PayloadType: 101, Name: "telephone-event", ClockRate: 8000, Channels: 1}}
	if _, err := Intersect(a, b); !errors.Is(err, ErrNoCommonCodec) {
		t.Fatalf("err = %v", err)
	}
}

// opus/48000/2 and opus/48000/1 are different streams and must not match.
func TestIntersectChannelsMatter(t *testing.T) {
	a := []Codec{{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2}}
	b := []Codec{{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 1}}
	if _, err := Intersect(a, b); !errors.Is(err, ErrNoCommonCodec) {
		t.Fatalf("err = %v", err)
	}
}

func TestNeedsRenumber(t *testing.T) {
	offer := []Codec{{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2}}
	same := []Codec{{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2}}
	if _, _, yes := NeedsRenumber(offer, same); yes {
		t.Error("false positive")
	}
	renum := []Codec{{PayloadType: 96, Name: "opus", ClockRate: 48000, Channels: 2}}
	o, a, yes := NeedsRenumber(offer, renum)
	if !yes || o.PayloadType != 111 || a.PayloadType != 96 {
		t.Errorf("got %v/%v/%v", o, a, yes)
	}
}

func TestBuildPrivateOfferStripsWebRTC(t *testing.T) {
	offer, err := Parse([]byte(browserOffer))
	if err != nil {
		t.Fatal(err)
	}
	b := Build{
		Address:   netip.MustParseAddr("10.77.0.2"),
		Port:      40000,
		Codecs:    Filter(offer.Audio.Codecs),
		Direction: offer.Audio.Direction,
		SessionID: 42, SessionVersion: 1,
	}
	out, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, forbidden := range []string{
		"ice-ufrag", "ice-pwd", "candidate", "fingerprint", "setup",
		"rtcp-mux", "SAVPF", "TLS", "192.168.1.44", "203.0.113.99",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("private offer leaks %q:\n%s", forbidden, s)
		}
	}
	if !strings.Contains(s, "m=audio 40000 RTP/AVP 111 0 8 110") {
		t.Errorf("wrong m= line:\n%s", s)
	}
	if !strings.Contains(s, "c=IN IP4 10.77.0.2") {
		t.Errorf("wrong c= line:\n%s", s)
	}
	// Payload numbers and codec parameters must survive verbatim.
	if !strings.Contains(s, "a=rtpmap:111 opus/48000/2") {
		t.Errorf("opus rtpmap lost:\n%s", s)
	}
	if !strings.Contains(s, "a=fmtp:111 minptime=10;useinbandfec=1") {
		t.Errorf("opus fmtp lost:\n%s", s)
	}
	if !strings.Contains(s, "a=rtpmap:110 telephone-event/48000") {
		t.Errorf("DTMF lost:\n%s", s)
	}
	// It must round-trip through our own parser.
	if _, err := Parse(out); err != nil {
		t.Fatalf("generated SDP does not re-parse: %v", err)
	}
}

func TestBuildWebRTCAnswer(t *testing.T) {
	fp := Fingerprint{Hash: "sha-256", Value: strings.ToUpper(strings.TrimSuffix(strings.Repeat("AB:", 32), ":"))}
	b := Build{
		Address:   netip.MustParseAddr("203.0.113.7"),
		Port:      30000,
		Codecs:    []Codec{{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2}},
		Direction: SendRecv,
		Secure:    true, DTLS: true, RTCPMux: true,
		ICEUfrag: "abcd", ICEPwd: "0123456789abcdef0123",
		Fingerprint: &fp, Setup: "passive",
		SessionID: 7, SessionVersion: 1,
	}
	out, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"m=audio 30000 UDP/TLS/RTP/SAVPF 111",
		"c=IN IP4 203.0.113.7",
		"a=ice-lite",
		"a=ice-ufrag:abcd",
		"a=ice-pwd:0123456789abcdef0123",
		"a=candidate:1 1 UDP",
		"typ host",
		"a=fingerprint:sha-256 AB:AB:",
		"a=setup:passive",
		"a=rtcp-mux",
		"a=rtpmap:111 opus/48000/2",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("answer missing %q:\n%s", want, s)
		}
	}
	if _, err := Parse(out); err != nil {
		t.Fatalf("generated SDP does not re-parse: %v", err)
	}
}

func TestBuildRejectsIncompleteDTLS(t *testing.T) {
	b := Build{
		Address: netip.MustParseAddr("203.0.113.7"), Port: 30000,
		Codecs: []Codec{{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1}},
		DTLS:   true, // no fingerprint / ICE credentials
	}
	if _, err := b.Marshal(); err == nil {
		t.Fatal("incomplete DTLS build accepted")
	}
}

// An answer must keep the offer's section count, with the extras declined
// and stripped of everything.
func TestMarshalDeclining(t *testing.T) {
	offer := &Session{MediaCount: 3}
	b := Build{
		Address: netip.MustParseAddr("10.0.0.1"), Port: 40000,
		Codecs: []Codec{{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1}},
	}
	out, err := b.MarshalDeclining(offer)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "m=audio 0 "); n != 2 {
		t.Errorf("declined sections = %d, want 2:\n%s", n, out)
	}
}

func TestDirectionReverse(t *testing.T) {
	for in, want := range map[Direction]Direction{
		SendRecv: SendRecv, SendOnly: RecvOnly, RecvOnly: SendOnly, Inactive: Inactive,
	} {
		if got := in.Reverse(); got != want {
			t.Errorf("%v.Reverse() = %v, want %v", in, got, want)
		}
	}
}
