package trunk

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/freesbc/freesbc/internal/media"
)

// cryptoLine is one parsed, SUPPORTED a=crypto offer: its tag, suite, and the
// decoded 30-byte SDES inline key value (master key ‖ salt).
type cryptoLine struct {
	tag      int
	suite    media.CryptoSuite
	keyValue []byte
}

// parseCryptoAttrs parses the VALUE part of each a=crypto line
// ("<tag> <suite> <key-params> [<session-params>]", RFC 4568 §9.1) into
// supported cryptoLines. A line is skipped — never accepted as a plain
// key — when its suite is unsupported, it is malformed, or it asks for
// something the SBC's SRTP contexts cannot do:
//
//   - more than one key-param, or a key with an MKI ("|<mki>:<length>"):
//     with an MKI every SRTP packet carries it, which the contexts do not
//     expect (RFC 4568 §6.1);
//   - any session parameter (KDR, UNENCRYPTED_SRTP, FEC_ORDER, WSH, ...):
//     each changes how packets are processed, and an endpoint must reject
//     a line whose parameters it does not implement (RFC 4568 §6.3).
//
// A key lifetime ("|2^20") is accepted: the SBC does not rekey, so it
// cannot honour a lifetime, but a lifetime alone does not change the
// packet format.
func parseCryptoAttrs(values []string) []cryptoLine {
	var out []cryptoLine
	for _, v := range values {
		fields := strings.Fields(v)
		// Exactly tag, suite and ONE key-param: a fourth field is a second
		// key-param or a session parameter, neither supported.
		if len(fields) != 3 {
			continue
		}
		tag, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		suite, ok := media.ParseCryptoSuite(fields[1])
		if !ok {
			continue
		}
		keyValue, ok := parseInlineKey(fields[2])
		if !ok {
			continue
		}
		out = append(out, cryptoLine{tag: tag, suite: suite, keyValue: keyValue})
	}
	return out
}

// parseInlineKey parses one key-param, "inline:<base64 key||salt>
// [|<lifetime>][|<mki>:<length>]", and returns the decoded key. It fails
// for any other key method, bad base64, a wrong key length, an MKI, a
// malformed lifetime, or anything after the lifetime.
func parseInlineKey(kp string) ([]byte, bool) {
	rest, ok := strings.CutPrefix(kp, "inline:")
	if !ok {
		return nil, false
	}
	parts := strings.Split(rest, "|")
	if len(parts) > 2 {
		return nil, false // a lifetime AND an MKI, or worse
	}
	if len(parts) == 2 && !isKeyLifetime(parts[1]) {
		return nil, false // an MKI (contains ':'), or garbage
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(decoded) != media.SDESKeyLen {
		return nil, false
	}
	return decoded, true
}

// isKeyLifetime reports whether s is an RFC 4568 §9.1 key lifetime:
// decimal digits, or "2^" followed by decimal digits.
func isKeyLifetime(s string) bool {
	s = strings.TrimPrefix(s, "2^")
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// cryptoAttrValue builds the VALUE of an a=crypto line advertising our key.
func cryptoAttrValue(tag int, suite media.CryptoSuite, keyValue []byte) string {
	return strconv.Itoa(tag) + " " + suite.String() +
		" inline:" + base64.StdEncoding.EncodeToString(keyValue)
}
