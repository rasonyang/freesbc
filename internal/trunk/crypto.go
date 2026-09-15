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
		suite, ok := media.ParseCryptoSuite(fields[1])
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
			if err != nil || len(decoded) != media.SDESKeyLen {
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

// cryptoAttrValue builds the VALUE of an a=crypto line advertising our key.
func cryptoAttrValue(tag int, suite media.CryptoSuite, keyValue []byte) string {
	return strconv.Itoa(tag) + " " + suite.String() +
		" inline:" + base64.StdEncoding.EncodeToString(keyValue)
}
