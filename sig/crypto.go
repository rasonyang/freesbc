package sig

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/freesbc/freesbc/media"
)

// cryptoLine is one parsed, SUPPORTED a=crypto offer: its tag, suite, and the
// decoded 30-byte SDES inline key value (master key ‖ salt).
type cryptoLine struct {
	tag      int
	suite    media.CryptoSuite
	keyValue []byte
}

// suiteByName maps RFC 4568 suite names to our supported CryptoSuite. Only the
// two AES_CM_128 suites are supported; anything else returns ok=false.
func suiteByName(name string) (media.CryptoSuite, bool) {
	switch name {
	case "AES_CM_128_HMAC_SHA1_80":
		return media.SuiteAES128CM80, true
	case "AES_CM_128_HMAC_SHA1_32":
		return media.SuiteAES128CM32, true
	default:
		return 0, false
	}
}

func suiteName(s media.CryptoSuite) string {
	if s == media.SuiteAES128CM32 {
		return "AES_CM_128_HMAC_SHA1_32"
	}
	return "AES_CM_128_HMAC_SHA1_80"
}

// parseCryptoAttrs parses the VALUE part of each a=crypto line
// ("<tag> <suite> inline:<base64>[|mki][ ...]") into supported cryptoLines.
// Unsupported suites, malformed lines, non-inline key methods, bad base64, and
// wrong key-value lengths are skipped. MKI and key-lifetime tokens after the
// base64 (separated by '|') are ignored (single master key per leg).
func parseCryptoAttrs(values []string) []cryptoLine {
	var out []cryptoLine
	for _, v := range values {
		fields := strings.Fields(v)
		if len(fields) < 3 {
			continue
		}
		tag, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		suite, ok := suiteByName(fields[1])
		if !ok {
			continue
		}
		// key-params: find the first "inline:" token.
		var keyValue []byte
		for _, kp := range fields[2:] {
			if !strings.HasPrefix(kp, "inline:") {
				continue
			}
			b64 := strings.TrimPrefix(kp, "inline:")
			if i := strings.IndexByte(b64, '|'); i >= 0 {
				b64 = b64[:i] // drop MKI / lifetime
			}
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err != nil || len(decoded) != media.SrtpMasterKeyValueLen() {
				break // malformed → this line has no usable key
			}
			keyValue = decoded
			break
		}
		if keyValue == nil {
			continue
		}
		out = append(out, cryptoLine{tag: tag, suite: suite, keyValue: keyValue})
	}
	return out
}

// selectCrypto returns the first offered line whose suite we support, honoring
// the offerer's preference order (RFC 4568 §5.1.2). ok=false if none.
func selectCrypto(offered []cryptoLine) (cryptoLine, bool) {
	if len(offered) == 0 {
		return cryptoLine{}, false
	}
	return offered[0], true // parseCryptoAttrs already dropped unsupported suites
}

// newCryptoKeyValue generates a fresh 30-byte SDES inline value.
func newCryptoKeyValue() ([]byte, error) {
	k := make([]byte, media.SrtpMasterKeyValueLen())
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// cryptoAttrValue builds the VALUE of an a=crypto line advertising our key.
func cryptoAttrValue(tag int, suite media.CryptoSuite, keyValue []byte) string {
	return strconv.Itoa(tag) + " " + suiteName(suite) +
		" inline:" + base64.StdEncoding.EncodeToString(keyValue)
}
