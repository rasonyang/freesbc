package sdp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file is SDES (RFC 4568): SRTP master keys carried in SDP
// "a=crypto" lines. Keys are secrets. Nothing here puts key material in an
// error, in String() or in any fmt verb of a Crypto; only Crypto.Value
// renders the key, and it exists for the SDP body alone.

// CryptoSuite is an RFC 4568 §6.2 / RFC 7714 crypto-suite name.
type CryptoSuite string

// The suites this package understands. Anything else in an offer is
// skipped, never an error (RFC 4568 §7.5: the answerer picks one it
// supports).
const (
	// SuiteAESCM128HMACSHA180 is mandatory to implement (RFC 4568 §6.2.1).
	SuiteAESCM128HMACSHA180 CryptoSuite = "AES_CM_128_HMAC_SHA1_80"
	SuiteAESCM128HMACSHA132 CryptoSuite = "AES_CM_128_HMAC_SHA1_32"
	// SuiteAEADAES128GCM is RFC 7714 §14.1.
	SuiteAEADAES128GCM CryptoSuite = "AEAD_AES_128_GCM"
)

// SupportedSuites lists every supported suite in the order FreeSBC prefers
// to offer them.
var SupportedSuites = []CryptoSuite{
	SuiteAESCM128HMACSHA180,
	SuiteAEADAES128GCM,
	SuiteAESCM128HMACSHA132,
}

// MaxCrypto bounds how many a=crypto lines of one section are considered.
const MaxCrypto = 8

// maxCryptoTag is the largest tag: RFC 4568 §9.1 allows 1 to 9 digits.
const maxCryptoTag = 999999999

// Lengths returns the master key and salt sizes in bytes (RFC 4568 §6.2.1,
// RFC 7714 §14.1). ok is false for an unsupported suite.
func (s CryptoSuite) Lengths() (key, salt int, ok bool) {
	switch s {
	case SuiteAESCM128HMACSHA180, SuiteAESCM128HMACSHA132:
		return 16, 14, true
	case SuiteAEADAES128GCM:
		return 16, 12, true
	}
	return 0, 0, false
}

// Supported reports whether the suite is one of SupportedSuites.
func (s CryptoSuite) Supported() bool { _, _, ok := s.Lengths(); return ok }

// Crypto is one usable SDES crypto attribute: the tag, the suite and the
// master key and salt. It has no MKI, session parameters or key lifetime:
// a line that needs any of those is not representable and is skipped by
// the parser (see ParseCrypto).
type Crypto struct {
	Tag   int
	Suite CryptoSuite
	Key   []byte
	Salt  []byte
}

// String renders the tag and suite only, never the key.
func (c Crypto) String() string { return fmt.Sprintf("crypto{tag=%d suite=%s}", c.Tag, c.Suite) }

// GoString keeps %#v from printing the key.
func (c Crypto) GoString() string { return c.String() }

// Format redacts the key under every verb, including %v and %+v, and when a
// Crypto is nested in a struct or slice that is printed.
func (c Crypto) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, c.String()) }

// Equal reports whether two attributes carry the same tag, suite, key and
// salt, comparing the secrets in constant time.
func (c Crypto) Equal(o Crypto) bool { return c.SameKey(o) && c.Tag == o.Tag }

// SameKey is Equal ignoring the tag: whether two lines key the same SRTP
// context.
func (c Crypto) SameKey(o Crypto) bool {
	if c.Suite != o.Suite {
		return false
	}
	k := subtle.ConstantTimeCompare(c.Key, o.Key)
	s := subtle.ConstantTimeCompare(c.Salt, o.Salt)
	return k&s == 1
}

// Validate checks the suite, tag and key/salt lengths. Its error never
// contains key material.
func (c Crypto) Validate() error {
	kl, sl, ok := c.Suite.Lengths()
	if !ok {
		return errors.New("sdp: crypto: unsupported suite")
	}
	if c.Tag < 1 || c.Tag > maxCryptoTag {
		return fmt.Errorf("sdp: crypto: tag %d out of range", c.Tag)
	}
	if len(c.Key) != kl || len(c.Salt) != sl {
		return fmt.Errorf("sdp: crypto: %s needs a %d-byte key and %d-byte salt, got %d and %d",
			c.Suite, kl, sl, len(c.Key), len(c.Salt))
	}
	return nil
}

// Value renders the attribute value ("<tag> <suite> inline:<base64>"), the
// part after "a=crypto:". It contains the key: use it only to build the
// SDP body, never for logging.
func (c Crypto) Value() string {
	mat := make([]byte, 0, len(c.Key)+len(c.Salt))
	mat = append(mat, c.Key...)
	mat = append(mat, c.Salt...)
	return strconv.Itoa(c.Tag) + " " + string(c.Suite) + " inline:" + base64.StdEncoding.EncodeToString(mat)
}

// NewCrypto generates fresh random key material for suite with the given
// tag, from crypto/rand.
func NewCrypto(tag int, suite CryptoSuite) (Crypto, error) {
	kl, sl, ok := suite.Lengths()
	if !ok {
		return Crypto{}, errors.New("sdp: crypto: unsupported suite")
	}
	if tag < 1 || tag > maxCryptoTag {
		return Crypto{}, fmt.Errorf("sdp: crypto: tag %d out of range", tag)
	}
	mat := make([]byte, kl+sl)
	if _, err := rand.Read(mat); err != nil {
		return Crypto{}, errors.New("sdp: crypto: random source failed")
	}
	return Crypto{Tag: tag, Suite: suite, Key: mat[:kl:kl], Salt: mat[kl:]}, nil
}

// OfferCrypto generates one fresh line per suite (all of SupportedSuites
// when none are given), tagged 1, 2, ... in the order given: the crypto
// attributes of an SDES offer. The caller keeps the result, since a
// re-offer on the same leg must repeat the keys.
func OfferCrypto(suites ...CryptoSuite) ([]Crypto, error) {
	if len(suites) == 0 {
		suites = SupportedSuites
	}
	out := make([]Crypto, 0, len(suites))
	for i, s := range suites {
		c, err := NewCrypto(i+1, s)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// SelectCrypto picks the line to accept from an offer: the first, in offer
// order, whose suite is in allowed (all supported suites when allowed is
// empty). RFC 4568 §7.5 has the answerer choose exactly one offered line.
func SelectCrypto(offered []Crypto, allowed ...CryptoSuite) (Crypto, bool) {
	for _, o := range offered {
		if o.Validate() != nil {
			continue
		}
		if len(allowed) == 0 {
			return o, true
		}
		for _, a := range allowed {
			if a == o.Suite {
				return o, true
			}
		}
	}
	return Crypto{}, false
}

// AnswerCrypto selects an offered line (see SelectCrypto) and generates
// FreeSBC's own key for it. The answer carries the selected line's tag and
// suite, so the peer knows which one was accepted; peer is the offerer's
// line (the key it sends with) and ours is the key FreeSBC sends with.
// ok is false when no offered line is usable.
func AnswerCrypto(offered []Crypto, allowed ...CryptoSuite) (peer, ours Crypto, ok bool, err error) {
	peer, ok = SelectCrypto(offered, allowed...)
	if !ok {
		return Crypto{}, Crypto{}, false, nil
	}
	ours, err = NewCrypto(peer.Tag, peer.Suite)
	if err != nil {
		return Crypto{}, Crypto{}, false, err
	}
	return peer, ours, true, nil
}

// ParseCrypto parses the value of one "a=crypto:" attribute. Its errors
// never quote the input (a misplaced key could sit in any field), so a key
// cannot reach a log through them.
//
// Policy, deliberately narrower than RFC 4568: a line is accepted only
// when it has a supported suite, exactly one inline key parameter with the
// exact master key||salt length of that suite, no MKI and no session
// parameters. A lifetime (a bare number or 2^N) is accepted and ignored:
// a peer that wants a shorter key life can re-INVITE with a new key. MKI
// and session parameters (KDR, UNENCRYPTED_SRTP, FEC_ORDER, WSH, ...)
// change how packets are processed, which the relay does not implement, so
// such a line is skipped; RFC 4568 §6.3 has the answerer reject an
// unrecognised session parameter, and skipping that line (another may be
// usable) is the same decision.
func ParseCrypto(value string) (Crypto, error) {
	const maxLen = 512
	if len(value) > maxLen {
		return Crypto{}, errors.New("sdp: crypto: line too long")
	}
	f := strings.Fields(value)
	if len(f) < 3 {
		return Crypto{}, errors.New("sdp: crypto: need tag, suite and key")
	}
	if len(f) > 3 {
		return Crypto{}, errors.New("sdp: crypto: session parameters are not supported")
	}
	tag, err := parseCryptoTag(f[0])
	if err != nil {
		return Crypto{}, err
	}
	suite := CryptoSuite(f[1])
	kl, sl, ok := suite.Lengths()
	if !ok {
		return Crypto{}, errors.New("sdp: crypto: unsupported suite")
	}
	rest, ok := strings.CutPrefix(f[2], "inline:")
	if !ok {
		return Crypto{}, errors.New("sdp: crypto: key method is not inline")
	}
	if strings.Contains(rest, ";") {
		return Crypto{}, errors.New("sdp: crypto: multiple key parameters are not supported")
	}
	parts := strings.Split(rest, "|")
	if len(parts) > 2 {
		return Crypto{}, errors.New("sdp: crypto: MKI is not supported")
	}
	if len(parts) == 2 && !validLifetime(parts[1]) {
		// Anything else after the key is an MKI (or garbage).
		return Crypto{}, errors.New("sdp: crypto: bad lifetime or unsupported MKI")
	}
	mat, err := decodeKeyBase64(parts[0])
	if err != nil {
		return Crypto{}, errors.New("sdp: crypto: key is not valid base64")
	}
	if len(mat) != kl+sl {
		return Crypto{}, fmt.Errorf("sdp: crypto: %s needs %d bytes of key and salt, got %d", suite, kl+sl, len(mat))
	}
	return Crypto{Tag: tag, Suite: suite, Key: mat[:kl:kl], Salt: mat[kl:]}, nil
}

func parseCryptoTag(s string) (int, error) {
	if len(s) == 0 || len(s) > 9 {
		return 0, errors.New("sdp: crypto: bad tag")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("sdp: crypto: bad tag")
		}
	}
	n, _ := strconv.Atoi(s)
	if n < 1 {
		return 0, errors.New("sdp: crypto: bad tag")
	}
	return n, nil
}

// validLifetime accepts the RFC 4568 §9.2 lifetime forms: digits, or 2^N.
func validLifetime(s string) bool {
	if len(s) > 12 {
		return false
	}
	s = strings.TrimPrefix(s, "2^")
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func decodeKeyBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Some stacks drop the padding.
	return base64.RawStdEncoding.DecodeString(s)
}

// parseCryptoAttrs collects the usable a=crypto lines of a media section:
// well-formed, supported, at most MaxCrypto, the first of any duplicated
// tag. Malformed and unsupported lines are skipped.
func parseCryptoAttrs(values []string) []Crypto {
	var out []Crypto
	seen := map[int]bool{}
	for _, v := range values {
		c, err := ParseCrypto(v)
		if err != nil || seen[c.Tag] {
			continue
		}
		seen[c.Tag] = true
		out = append(out, c)
		if len(out) == MaxCrypto {
			break
		}
	}
	return out
}
