package sdp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func b64(n int, fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, n))
}

func TestParseCryptoAccepts(t *testing.T) {
	cases := []struct {
		name, in string
		suite    CryptoSuite
		tag      int
	}{
		{"cm80", "1 AES_CM_128_HMAC_SHA1_80 inline:" + b64(30, 1), SuiteAESCM128HMACSHA180, 1},
		{"cm32", "2 AES_CM_128_HMAC_SHA1_32 inline:" + b64(30, 2), SuiteAESCM128HMACSHA132, 2},
		{"gcm", "3 AEAD_AES_128_GCM inline:" + b64(28, 3), SuiteAEADAES128GCM, 3},
		{"lifetime pow", "1 AES_CM_128_HMAC_SHA1_80 inline:" + b64(30, 1) + "|2^31", SuiteAESCM128HMACSHA180, 1},
		{"lifetime int", "1 AES_CM_128_HMAC_SHA1_80 inline:" + b64(30, 1) + "|1048576", SuiteAESCM128HMACSHA180, 1},
		{"unpadded", "1 AES_CM_128_HMAC_SHA1_80 inline:" + strings.TrimRight(b64(30, 1), "="), SuiteAESCM128HMACSHA180, 1},
	}
	for _, c := range cases {
		got, err := ParseCrypto(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got.Suite != c.suite || got.Tag != c.tag {
			t.Errorf("%s: got %v", c.name, got)
		}
		if err := got.Validate(); err != nil {
			t.Errorf("%s: validate: %v", c.name, err)
		}
	}
}

func TestParseCryptoRejects(t *testing.T) {
	good := b64(30, 7)
	cases := map[string]string{
		"empty":           "",
		"no key":          "1 AES_CM_128_HMAC_SHA1_80",
		"unknown suite":   "1 F8_128_HMAC_SHA1_80 inline:" + good,
		"aes256":          "1 AES_256_CM_HMAC_SHA1_80 inline:" + good,
		"short key":       "1 AES_CM_128_HMAC_SHA1_80 inline:" + b64(29, 7),
		"long key":        "1 AES_CM_128_HMAC_SHA1_80 inline:" + b64(31, 7),
		"gcm cm length":   "1 AEAD_AES_128_GCM inline:" + good,
		"cm gcm length":   "1 AES_CM_128_HMAC_SHA1_80 inline:" + b64(28, 7),
		"bad base64":      "1 AES_CM_128_HMAC_SHA1_80 inline:!!!!",
		"not inline":      "1 AES_CM_128_HMAC_SHA1_80 uri:" + good,
		"mki":             "1 AES_CM_128_HMAC_SHA1_80 inline:" + good + "|2^20|1:4",
		"mki only":        "1 AES_CM_128_HMAC_SHA1_80 inline:" + good + "|1:4",
		"bad lifetime":    "1 AES_CM_128_HMAC_SHA1_80 inline:" + good + "|abc",
		"two keys":        "1 AES_CM_128_HMAC_SHA1_80 inline:" + good + ";inline:" + good,
		"session param":   "1 AES_CM_128_HMAC_SHA1_80 inline:" + good + " UNENCRYPTED_SRTP",
		"kdr":             "1 AES_CM_128_HMAC_SHA1_80 inline:" + good + " KDR=3",
		"tag zero":        "0 AES_CM_128_HMAC_SHA1_80 inline:" + good,
		"tag letters":     "x AES_CM_128_HMAC_SHA1_80 inline:" + good,
		"tag too long":    "1234567890 AES_CM_128_HMAC_SHA1_80 inline:" + good,
		"line too long":   "1 AES_CM_128_HMAC_SHA1_80 inline:" + strings.Repeat("A", 600),
		"negative tag":    "-1 AES_CM_128_HMAC_SHA1_80 inline:" + good,
		"empty lifetime":  "1 AES_CM_128_HMAC_SHA1_80 inline:" + good + "|",
		"bare caret life": "1 AES_CM_128_HMAC_SHA1_80 inline:" + good + "|2^",
	}
	for name, in := range cases {
		if c, err := ParseCrypto(in); err == nil {
			t.Errorf("%s: accepted: %v", name, c)
		}
	}
}

func TestCryptoErrorsNeverContainKeys(t *testing.T) {
	key := b64(30, 0x5a)
	inputs := []string{
		"1 AES_CM_128_HMAC_SHA1_80 inline:" + key + "|2^20|1:4",
		"1 AES_CM_128_HMAC_SHA1_80 inline:" + key + " KDR=3",
		"1 NOPE inline:" + key,
		"1 AES_CM_128_HMAC_SHA1_80 inline:" + key + ";inline:" + key,
		"1 AES_CM_128_HMAC_SHA1_80 inline:" + b64(31, 0x5a),
		"1 AES_CM_128_HMAC_SHA1_80 inline:" + key + "|zzz",
	}
	for _, in := range inputs {
		_, err := ParseCrypto(in)
		if err == nil {
			t.Fatalf("accepted %q", in)
		}
		if strings.Contains(err.Error(), "Wlpa") || strings.Contains(err.Error(), key) {
			t.Errorf("error leaks key: %v", err)
		}
	}
	c, _ := NewCrypto(1, SuiteAESCM128HMACSHA180)
	enc := base64.StdEncoding.EncodeToString(append(append([]byte{}, c.Key...), c.Salt...))
	for _, s := range []string{
		c.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c),
		fmt.Sprintf("%v", []Crypto{c}), fmt.Sprintf("%+v", &Audio{Crypto: []Crypto{c}}),
		fmt.Sprintf("%x", c), fmt.Sprintf("%s", c),
	} {
		if strings.Contains(s, enc) || strings.Contains(s, fmt.Sprintf("%x", c.Key)) {
			t.Errorf("formatted Crypto leaks key: %s", s)
		}
	}
	bad := Crypto{Tag: 1, Suite: SuiteAESCM128HMACSHA180, Key: c.Key[:5], Salt: c.Salt}
	if err := bad.Validate(); err == nil || strings.Contains(err.Error(), enc) {
		t.Errorf("validate: %v", err)
	}
}

const sdesOffer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n" +
	"m=audio 4000 RTP/SAVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"

func TestParseOfferCryptoLines(t *testing.T) {
	body := sdesOffer +
		"a=crypto:1 UNKNOWN_SUITE inline:" + b64(30, 1) + "\r\n" +
		"a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:" + b64(30, 2) + "|1:4\r\n" +
		"a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:" + b64(30, 3) + " KDR=1\r\n" +
		"a=crypto:4 AEAD_AES_128_GCM inline:" + b64(28, 4) + "\r\n" +
		"a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:" + b64(30, 5) + "|2^31\r\n" +
		"a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:" + b64(30, 6) + "\r\n"
	s, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Audio.SDES() {
		t.Error("SDES() false for RTP/SAVP")
	}
	if len(s.Audio.Crypto) != 2 || s.Audio.Crypto[0].Tag != 4 || s.Audio.Crypto[1].Tag != 5 {
		t.Fatalf("crypto = %v", s.Audio.Crypto)
	}
	peer, ours, ok, err := AnswerCrypto(s.Audio.Crypto)
	if err != nil || !ok {
		t.Fatalf("answer: %v %v", ok, err)
	}
	if peer.Tag != 4 || peer.Suite != SuiteAEADAES128GCM || ours.Tag != 4 || ours.Suite != SuiteAEADAES128GCM {
		t.Errorf("peer %v ours %v", peer, ours)
	}
	if ours.SameKey(peer) {
		t.Error("answer reused the offerer's key")
	}
	// Restricting the allowed suites picks the next offered line.
	peer, _, ok, _ = AnswerCrypto(s.Audio.Crypto, SuiteAESCM128HMACSHA180)
	if !ok || peer.Tag != 5 {
		t.Errorf("allowed=cm80 picked %v", peer)
	}
	if _, _, ok, _ = AnswerCrypto(s.Audio.Crypto, SuiteAESCM128HMACSHA132); ok {
		t.Error("selected a suite that was not offered")
	}
}

func TestParseNoCryptoOnPlainOrDTLS(t *testing.T) {
	s, err := Parse([]byte(strings.Replace(sdesOffer, "RTP/SAVP", "RTP/AVP", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if s.Audio.SDES() || len(s.Audio.Crypto) != 0 {
		t.Error("plain offer reads as SDES")
	}
}

func TestBuildSDESRoundTrip(t *testing.T) {
	offer, err := OfferCrypto()
	if err != nil {
		t.Fatal(err)
	}
	if len(offer) != len(SupportedSuites) {
		t.Fatalf("offer has %d lines", len(offer))
	}
	b := Build{
		Address: netip.MustParseAddr("203.0.113.7"),
		Port:    20000,
		Codecs:  []Codec{{PayloadType: 0, Name: "PCMU", ClockRate: 8000}},
		Crypto:  offer,
	}
	body, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "m=audio 20000 RTP/SAVP 0") {
		t.Fatalf("body:\n%s", body)
	}
	if strings.Count(string(body), "a=crypto:") != len(offer) {
		t.Fatalf("body:\n%s", body)
	}
	s, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Audio.Crypto) != len(offer) {
		t.Fatalf("parsed %d lines", len(s.Audio.Crypto))
	}
	for i := range offer {
		if !offer[i].Equal(s.Audio.Crypto[i]) {
			t.Errorf("line %d changed in round trip", i)
		}
	}
}

func TestBuildPlainUnchangedAndBadCrypto(t *testing.T) {
	b := Build{
		Address: netip.MustParseAddr("203.0.113.7"),
		Port:    20000,
		Codecs:  []Codec{{PayloadType: 0, Name: "PCMU", ClockRate: 8000}},
	}
	body, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "m=audio 20000 RTP/AVP 0") || strings.Contains(string(body), "crypto") {
		t.Errorf("plain body changed:\n%s", body)
	}
	b.Crypto = []Crypto{{Tag: 1, Suite: SuiteAESCM128HMACSHA180, Key: []byte{1, 2, 3}, Salt: []byte{4}}}
	if _, err := b.Marshal(); err == nil {
		t.Error("built a body with a short key")
	}
	good, _ := NewCrypto(1, SuiteAESCM128HMACSHA180)
	b.Crypto = []Crypto{good}
	b.DTLS = true
	if _, err := b.Marshal(); err == nil {
		t.Error("built SDES together with DTLS")
	}
}

func TestNewCryptoIsRandomAndSized(t *testing.T) {
	for _, s := range SupportedSuites {
		a, err := NewCrypto(1, s)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := NewCrypto(1, s)
		if a.Validate() != nil || a.SameKey(b) {
			t.Errorf("%s: bad or repeated key material", s)
		}
	}
	if _, err := NewCrypto(1, "NOPE"); err == nil {
		t.Error("generated a key for an unknown suite")
	}
	if _, err := NewCrypto(0, SuiteAESCM128HMACSHA180); err == nil {
		t.Error("accepted tag 0")
	}
}

func FuzzParseCrypto(f *testing.F) {
	f.Add("1 AES_CM_128_HMAC_SHA1_80 inline:" + b64(30, 1))
	f.Add("2 AEAD_AES_128_GCM inline:" + b64(28, 2) + "|2^31")
	f.Add("1 AES_CM_128_HMAC_SHA1_32 inline:" + b64(30, 3) + "|1:4 KDR=2")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		c, err := ParseCrypto(in)
		if err != nil {
			if len(in) > 20 && strings.Contains(err.Error(), in[len(in)-20:]) {
				t.Fatalf("error echoes input: %v", err)
			}
			return
		}
		if c.Validate() != nil {
			t.Fatalf("parsed line fails Validate: %v", c)
		}
		again, err := ParseCrypto(c.Value())
		if err != nil || !again.Equal(c) {
			t.Fatalf("Value does not round-trip: %v", err)
		}
		// Whatever the input, a body built around it must parse.
		body := sdesOffer + "a=crypto:" + in + "\r\n"
		if _, err := Parse([]byte(body)); err != nil && !strings.ContainsAny(in, "\r\n\x00") {
			// A weird line may make the body unparsable, but only when it
			// breaks the SDP line structure, which ParseCrypto accepted.
			t.Fatalf("accepted crypto line broke Parse: %v", err)
		}
	})
}
