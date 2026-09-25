package trunk

import (
	"encoding/base64"
	"testing"

	"github.com/freesbc/freesbc/internal/media"
)

func b64key30() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 30)) // 30 zero bytes
}

func TestParseCryptoValidBothSuites(t *testing.T) {
	lines := parseCryptoAttrs([]string{
		"1 AES_CM_128_HMAC_SHA1_80 inline:" + b64key30(),
		"2 AES_CM_128_HMAC_SHA1_32 inline:" + b64key30(),
	})
	if len(lines) != 2 {
		t.Fatalf("want 2 parsed lines, got %d", len(lines))
	}
	if lines[0].tag != 1 || lines[0].suite != media.SuiteAES128CM80 {
		t.Errorf("line 0 = tag %d suite %v", lines[0].tag, lines[0].suite)
	}
	if lines[1].suite != media.SuiteAES128CM32 {
		t.Errorf("line 1 suite = %v want 32", lines[1].suite)
	}
	if len(lines[0].keyValue) != 30 {
		t.Errorf("keyValue len = %d want 30", len(lines[0].keyValue))
	}
}

func TestParseCryptoSkipsUnsupportedSuite(t *testing.T) {
	lines := parseCryptoAttrs([]string{
		"1 AES_256_CM_HMAC_SHA1_80 inline:" + base64.StdEncoding.EncodeToString(make([]byte, 46)),
		"2 AES_CM_128_HMAC_SHA1_80 inline:" + b64key30(),
	})
	if len(lines) != 1 || lines[0].tag != 2 {
		t.Fatalf("want only the supported 128-bit line (tag 2), got %+v", lines)
	}
}

func TestParseCryptoSkipsMalformed(t *testing.T) {
	cases := []string{
		"1 AES_CM_128_HMAC_SHA1_80 inline:!!!notbase64!!!",
		"1 AES_CM_128_HMAC_SHA1_80 inline:" + base64.StdEncoding.EncodeToString(make([]byte, 10)), // wrong len
		"1 AES_CM_128_HMAC_SHA1_80",                                                               // no inline
		"garbage",
	}
	for _, c := range cases {
		if lines := parseCryptoAttrs([]string{c}); len(lines) != 0 {
			t.Errorf("%q should parse to nothing, got %+v", c, lines)
		}
	}
}

// An MKI changes the SRTP packet format (RFC 4568 §6.1), so a key carrying
// one is rejected; a lifetime alone does not, so it is accepted.
// audit: P2-TRK-012
func TestParseCryptoRejectsMKIAcceptsLifetime(t *testing.T) {
	for _, kp := range []string{"|2^20|1:4", "|1:4", "|2^20|1:4|x", "|lifetime"} {
		if lines := parseCryptoAttrs([]string{"1 AES_CM_128_HMAC_SHA1_80 inline:" + b64key30() + kp}); len(lines) != 0 {
			t.Errorf("key-param suffix %q must be rejected, got %+v", kp, lines)
		}
	}
	for _, kp := range []string{"|2^20", "|1048576"} {
		lines := parseCryptoAttrs([]string{"1 AES_CM_128_HMAC_SHA1_80 inline:" + b64key30() + kp})
		if len(lines) != 1 || len(lines[0].keyValue) != 30 {
			t.Errorf("lifetime %q must be accepted, got %+v", kp, lines)
		}
	}
	if lines := parseCryptoAttrs([]string{"1 AES_CM_128_HMAC_SHA1_80 inline:" + b64key30() + " KDR=1"}); len(lines) != 0 {
		t.Errorf("a session parameter must be rejected, got %+v", lines)
	}
}

func TestCryptoAttrValueRoundTrip(t *testing.T) {
	key := media.NewSDESKey()
	v := cryptoAttrValue(1, media.SuiteAES128CM80, key)
	lines := parseCryptoAttrs([]string{v})
	if len(lines) != 1 || lines[0].tag != 1 || lines[0].suite != media.SuiteAES128CM80 {
		t.Fatalf("generated attr didn't round-trip: %q → %+v", v, lines)
	}
	if string(lines[0].keyValue) != string(key) {
		t.Fatal("round-tripped key value differs")
	}
}

// firstCryptoLine is the test-side equivalent of what onInvite and
// processAnswerSDP do inline: parseCryptoAttrs has already dropped every
// unsupported suite, so the first surviving line is the selected one
// (RFC 4568 §5.1.2).
func firstCryptoLine(lines []cryptoLine) (cryptoLine, bool) {
	if len(lines) == 0 {
		return cryptoLine{}, false
	}
	return lines[0], true
}
