package sip

import (
	"crypto/rand"
	"encoding/base64"
)

// randomToken returns n bytes of CSPRNG output in URL-safe base64.
//
// It panics when crypto/rand fails. That does not happen in practice, and
// every caller here is producing a value whose whole worth is that it
// cannot be guessed — a branch that must be unique, a capability token
// that addresses a device — so a fallback to anything predictable would be
// worse than stopping.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("sip: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewBranch generates an RFC 3261 §8.1.1.7 branch parameter, carrying the
// magic cookie that marks it as RFC 3261 compliant.
func NewBranch() string { return "z9hG4bK" + randomToken(12) }

// NewToken generates an opaque identifier for FreeSBC's own use — 12 bytes
// of CSPRNG output, long enough not to be guessable.
func NewToken() string { return randomToken(12) }
