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

func TestParseCryptoIgnoresMKIAndLifetime(t *testing.T) {
	lines := parseCryptoAttrs([]string{
		"1 AES_CM_128_HMAC_SHA1_80 inline:" + b64key30() + "|2^20|1:4",
	})
	if len(lines) != 1 || len(lines[0].keyValue) != 30 {
		t.Fatalf("MKI/lifetime after key must be ignored, got %+v", lines)
	}
}

func TestSelectCryptoFirstSupportedInOrder(t *testing.T) {
	offered := []cryptoLine{
		{tag: 5, suite: media.SuiteAES128CM32, keyValue: make([]byte, 30)},
		{tag: 6, suite: media.SuiteAES128CM80, keyValue: make([]byte, 30)},
	}
	got, ok := selectCrypto(offered)
	if !ok || got.tag != 5 {
		t.Fatalf("select must honor offered order (tag 5 first), got %+v ok=%v", got, ok)
	}
	if _, ok := selectCrypto(nil); ok {
		t.Fatal("empty offered → ok=false")
	}
}

func TestNewCryptoKeyValueLengthAndRandomness(t *testing.T) {
	a, err := newCryptoKeyValue()
	if err != nil || len(a) != 30 {
		t.Fatalf("key value len=%d err=%v", len(a), err)
	}
	b, _ := newCryptoKeyValue()
	if string(a) == string(b) {
		t.Fatal("two generated keys are identical (not random)")
	}
}

func TestCryptoAttrValueRoundTrip(t *testing.T) {
	key, _ := newCryptoKeyValue()
	v := cryptoAttrValue(1, media.SuiteAES128CM80, key)
	lines := parseCryptoAttrs([]string{v})
	if len(lines) != 1 || lines[0].tag != 1 || lines[0].suite != media.SuiteAES128CM80 {
		t.Fatalf("generated attr didn't round-trip: %q → %+v", v, lines)
	}
	if string(lines[0].keyValue) != string(key) {
		t.Fatal("round-tripped key value differs")
	}
}
