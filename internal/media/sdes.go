package media

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/pion/srtp/v3"
)

// This file is the SDES-SRTP leg (RFC 4568): a side of a plain Session
// whose RTP and RTCP are SRTP/SRTCP keyed by master keys that signaling
// negotiated, not by DTLS. The side keeps its ordinary UDP port pair and
// latch; the relay decrypts what arrives from it and encrypts what is sent
// to it. Nothing here parses SDP: the package knows keys, not a=crypto.
//
// An SDES side fails closed. As soon as either key is set the side is an
// SDES side, and a direction whose key has not been set yet drops its
// packets (counted in LegStats) instead of sending or accepting plaintext.
// rtcp-mux is not supported (the relay keeps RTCP on its own port pair), so
// signaling must not offer or accept it on an SDES leg.

// SDESSuite names an SDES crypto suite (RFC 4568 §6.2, RFC 7714 §14.1).
type SDESSuite string

const (
	SDESAESCM128HMACSHA180 SDESSuite = "AES_CM_128_HMAC_SHA1_80"
	SDESAESCM128HMACSHA132 SDESSuite = "AES_CM_128_HMAC_SHA1_32"
	SDESAEADAES128GCM      SDESSuite = "AEAD_AES_128_GCM"
)

// SDESKey is the master key and salt of one direction. It is a secret:
// every fmt verb prints the suite only.
type SDESKey struct {
	Suite SDESSuite
	Key   []byte
	Salt  []byte
}

// String names the suite only, never the key.
func (k SDESKey) String() string { return "sdes-key{" + string(k.Suite) + "}" }

// GoString keeps %#v from printing the key.
func (k SDESKey) GoString() string { return k.String() }

// Format redacts the key under every verb.
func (k SDESKey) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, k.String()) }

// ErrSDESKey is returned for a key that cannot build an SRTP context. It
// never carries key material.
var ErrSDESKey = errors.New("media: invalid SDES key")

func (k SDESKey) profile() (srtp.ProtectionProfile, error) {
	var p srtp.ProtectionProfile
	switch k.Suite {
	case SDESAESCM128HMACSHA180:
		p = srtp.ProtectionProfileAes128CmHmacSha1_80
	case SDESAESCM128HMACSHA132:
		p = srtp.ProtectionProfileAes128CmHmacSha1_32
	case SDESAEADAES128GCM:
		p = srtp.ProtectionProfileAeadAes128Gcm
	default:
		return 0, fmt.Errorf("%w: unsupported suite", ErrSDESKey)
	}
	return p, nil
}

func (k SDESKey) clone() SDESKey {
	return SDESKey{Suite: k.Suite, Key: append([]byte(nil), k.Key...), Salt: append([]byte(nil), k.Salt...)}
}

func (k SDESKey) equal(o SDESKey) bool {
	if k.Suite != o.Suite {
		return false
	}
	return subtle.ConstantTimeCompare(k.Key, o.Key)&subtle.ConstantTimeCompare(k.Salt, o.Salt) == 1
}

// sdesDir is one direction of an SDES leg: the key in force and the
// context built from it.
type sdesDir struct {
	mu  sync.Mutex // serializes set; the relay only reads ctx
	key SDESKey
	ctx atomic.Pointer[SRTPContext]
}

// set installs k. An identical key is a no-op, so the live context keeps
// its rollover counter and replay window; a different one replaces the
// context atomically (relay goroutines in flight finish on the old one).
// On error the previous key stays in force.
func (d *sdesDir) set(k SDESKey) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Load() != nil && d.key.equal(k) {
		return nil
	}
	profile, err := k.profile()
	if err != nil {
		return err
	}
	ctx, err := newSRTPContextFromKeys(profile, k.Key, k.Salt)
	if err != nil {
		return ErrSDESKey // pion/our lengths error; no key bytes in it
	}
	d.key = k.clone()
	d.ctx.Store(ctx)
	return nil
}

// sdesLeg is the SDES state of one side: `in` unprotects what the side
// sends, `out` protects what is sent to it.
type sdesLeg struct {
	in, out sdesDir
}

// sdesFor returns side's SDES state, creating it (which turns the side into
// an SDES side) on first use.
func (s *Session) sdesFor(side Side) *sdesLeg {
	if l := s.sdes[side].Load(); l != nil {
		return l
	}
	s.sdes[side].CompareAndSwap(nil, &sdesLeg{})
	return s.sdes[side].Load()
}

// SetSDESRemote sets the key side's peer protects its packets with (the
// a=crypto line the peer sent): the relay decrypts what arrives from the
// side with it. Safe on a running session. The same key again changes
// nothing; a new key replaces the decrypt context without touching the
// ports or the latch.
func (s *Session) SetSDESRemote(side Side, k SDESKey) error {
	return s.sdesFor(side).in.set(k)
}

// SetSDESLocal sets the key FreeSBC protects packets sent to side with (the
// a=crypto line FreeSBC put in its SDP). Same semantics as SetSDESRemote.
func (s *Session) SetSDESLocal(side Side, k SDESKey) error {
	return s.sdesFor(side).out.set(k)
}

// SDESEnabled reports whether side is an SDES side.
func (s *Session) SDESEnabled(side Side) bool { return s.sdes[side].Load() != nil }
