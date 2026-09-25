package media

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
	"github.com/pion/transport/v4/replaydetector"
)

// SDESKeyLen is the length of an SDES inline key value for the supported
// AES_CM_128 suites: a 16-byte master key concatenated with a 14-byte
// master salt. The signaling plane validates decoded keys against it.
const SDESKeyLen = 30

// CryptoSuite identifies an SDES/SRTP crypto suite. Only the two AES_CM_128
// suites are supported (spec §1.3).
type CryptoSuite int

const (
	SuiteAES128CM80 CryptoSuite = iota // AES_CM_128_HMAC_SHA1_80
	SuiteAES128CM32                    // AES_CM_128_HMAC_SHA1_32
)

// ParseCryptoSuite maps an RFC 4568 suite name to a CryptoSuite. Anything
// outside the two supported AES_CM_128 suites returns ok=false.
func ParseCryptoSuite(name string) (CryptoSuite, bool) {
	switch name {
	case "AES_CM_128_HMAC_SHA1_80":
		return SuiteAES128CM80, true
	case "AES_CM_128_HMAC_SHA1_32":
		return SuiteAES128CM32, true
	default:
		return 0, false
	}
}

// String is the RFC 4568 name of the suite, as it appears in an a=crypto
// line.
func (s CryptoSuite) String() string {
	if s == SuiteAES128CM32 {
		return "AES_CM_128_HMAC_SHA1_32"
	}
	return "AES_CM_128_HMAC_SHA1_80"
}

// NewSDESKey generates a fresh SDES inline value (master key ‖ salt) from
// the CSPRNG. crypto/rand.Read cannot fail on any supported platform — it
// panics rather than returning a short read — so there is no error to
// report and no partially-random key to guard against.
func NewSDESKey() []byte {
	k := make([]byte, SDESKeyLen)
	rand.Read(k)
	return k
}

func (s CryptoSuite) profile() srtp.ProtectionProfile {
	if s == SuiteAES128CM32 {
		return srtp.ProtectionProfileAes128CmHmacSha1_32
	}
	return srtp.ProtectionProfileAes128CmHmacSha1_80
}

// SRTPContext protects/unprotects the RTP and RTCP of ONE stream with one
// SRTP master key. pion's *srtp.Context has no internal lock, and in the relay
// the same context is used by both the RTP-forward and RTCP-forward goroutines
// of a direction, so every call is serialized by mu.
//
// No per-packet heap allocation (P2-MED-007). rtpHdr/rtcpHdr are handed to
// pion instead of nil, which would make it allocate a header per packet,
// and the output never comes from pion's own allocation:
//
//   - The relays call the *Into variants with a destination buffer they
//     own, sized for the SRTP overhead — usually the packet's own read
//     buffer, so the transform runs in place. Nothing is allocated.
//   - protectRTP/unprotectRTP and the RTCP pair leave their input
//     untouched and return a slice carved from slab, a chunk that is only
//     ever appended to: a returned slice is never overwritten by a later
//     call, and one allocation serves many packets.
type SRTPContext struct {
	mu      sync.Mutex
	ctx     *srtp.Context
	rtpHdr  rtp.Header
	rtcpHdr rtcp.Header
	slab    []byte
}

// srtpMaxOverhead is the most SRTP/SRTCP adds to a packet with the
// AES_CM_128 profiles and no MKI: a 10-byte auth tag, plus the 4-byte
// E-flag/index word for SRTCP. Rounded up to 16 for slack. A destination
// with this much capacity past the plaintext never makes pion allocate.
const srtpMaxOverhead = 16

// srtpSlabSize is how much output one slab allocation covers: about 80
// full-size voice packets.
const srtpSlabSize = 16 << 10

// fromSlab runs one pion transform whose output is at most max bytes into
// a fresh stretch of the slab, then marks it used. Callers hold mu.
func (c *SRTPContext) fromSlab(max int, transform func(dst []byte) ([]byte, error)) ([]byte, bool) {
	if cap(c.slab)-len(c.slab) < max {
		c.slab = make([]byte, 0, srtpSlabSize+max)
	}
	off := len(c.slab)
	out, err := transform(c.slab[off : off : off+max])
	if err != nil {
		return nil, false
	}
	if len(out) <= max {
		c.slab = c.slab[:off+len(out)]
	}
	return out, true
}

// Cryptex (RFC 9335) header-extension profiles. They are only meaningful
// on an SRTP packet whose header extension is encrypted, and pion's
// decrypt side treats them that way, so a plaintext RTP packet carrying
// one would be protected into SRTP that no Cryptex-less receiver —
// including ours — can unprotect (P3-MED-001).
const (
	cryptexProfileOneByte = 0xC0DE
	cryptexProfileTwoByte = 0xC2DE
)

// hasCryptexProfile reports whether plaintext RTP pkt carries a header
// extension with a Cryptex profile. A malformed header reports false and
// is left for pion to reject.
func hasCryptexProfile(pkt []byte) bool {
	if len(pkt) < 12 || pkt[0]&0x10 == 0 {
		return false
	}
	off := 12 + 4*int(pkt[0]&0x0f)
	if len(pkt) < off+2 {
		return false
	}
	p := binary.BigEndian.Uint16(pkt[off:])
	return p == cryptexProfileOneByte || p == cryptexProfileTwoByte
}

// NewSRTPContext builds a context from a 30-byte SDES inline value
// (16-byte master key followed by a 14-byte master salt), with replay
// protection enabled (RFC 3711 §3.3.2/§3.4.2 MUST): a
// replayed/too-old packet fails unprotect and is dropped by the relay's
// existing fail-closed path — pion's default is no replay protection, which
// would let a captured valid packet be re-injected indefinitely. The
// windows are per-context (one context protects exactly one stream of one
// direction), so they don't interact across legs or sides.
func NewSRTPContext(suite CryptoSuite, keyValue []byte) (*SRTPContext, error) {
	if len(keyValue) != SDESKeyLen {
		return nil, fmt.Errorf("srtp key value must be %d bytes, got %d", SDESKeyLen, len(keyValue))
	}
	return newContext(suite.profile(), keyValue[:16], keyValue[16:30])
}

// newContext is the one place an *srtp.Context is built, for both the SDES
// and the DTLS-SRTP constructors. Replay protection is enabled here and
// nowhere else: pion's default is none, which would let a captured valid
// packet be re-injected indefinitely.
func newContext(profile srtp.ProtectionProfile, masterKey, masterSalt []byte) (*SRTPContext, error) {
	ctx, err := srtp.CreateContext(masterKey, masterSalt, profile,
		srtp.SRTPReplayDetectorFactory(func() replaydetector.ReplayDetector {
			return newTokenReplayDetector(srtpReplayWindow, maxSRTPIndex)
		}),
		srtp.SRTCPReplayDetectorFactory(func() replaydetector.ReplayDetector {
			return newTokenReplayDetector(srtcpReplayWindow, maxSRTCPIndex)
		}))
	if err != nil {
		return nil, fmt.Errorf("srtp create context: %w", err)
	}
	return &SRTPContext{ctx: ctx}, nil
}

// srtpReplayWindow and srtcpReplayWindow are the replay-protection window
// sizes passed to pion. 64 covers any plausible jitter/out-of-
// order arrival on a single media stream; RTCP gets 128 since its
// compounds are rarer and arrive more irregularly. Both bound the index
// space a replayer can claim: anything older than the window (or already
// seen) fails authentication.
const (
	srtpReplayWindow  = 64
	srtcpReplayWindow = 128
)

// maxSRTPIndex and maxSRTCPIndex are the index spaces pion's own
// SRTPReplayProtection/SRTCPReplayProtection options use: a 48-bit
// ROC‖SEQ for SRTP (RFC 3711 §3.3.1), 31 bits for SRTCP (§3.4).
const (
	maxSRTPIndex  = 1<<48 - 1
	maxSRTCPIndex = 0x7FFFFFFF
)

// tokenReplayDetector is pion's own sliding-window replay detector
// (replaydetector.New — the one SRTPReplayProtection installs) behind a
// Check that does not allocate. pion's Check returns a fresh closure per
// packet, the one heap allocation left on the unprotect path
// (P2-MED-007); the detector's CheckSeq/Accept token API is the same
// check and commit without it. Check stores the token and returns a
// method value bound once at construction.
//
// That is safe because pion calls Check and then, only after the packet
// authenticates, the returned func on the same detector, within one
// Decrypt call — and every Decrypt on an SRTPContext is serialized by its
// mu, so no second Check can land in between.
type tokenReplayDetector struct {
	inner  replaydetector.CheckAccepter
	tok    replaydetector.Token
	accept func() bool
}

func newTokenReplayDetector(window uint, maxSeq uint64) replaydetector.ReplayDetector {
	inner, ok := replaydetector.New(window, maxSeq).(replaydetector.CheckAccepter)
	if !ok {
		// A pion release whose detector lost the token API: fall back to
		// the allocating one rather than disabling replay protection.
		return replaydetector.New(window, maxSeq)
	}
	d := &tokenReplayDetector{inner: inner}
	d.accept = d.commit
	return d
}

func (d *tokenReplayDetector) Check(seq uint64) (func() bool, bool) {
	d.tok = d.inner.CheckSeq(seq)
	if !d.tok.Passed() {
		return rejectReplay, false
	}
	return d.accept, true
}

func (d *tokenReplayDetector) commit() bool { return d.inner.Accept(d.tok) }

func rejectReplay() bool { return false }

// protectRTP encrypts a plaintext RTP packet, leaving pkt untouched.
// ok=false on failure (the caller drops the packet).
//
// A plaintext packet with a Cryptex header-extension profile is refused:
// Cryptex is not negotiated, so its SRTP could never be unprotected.
func (c *SRTPContext) protectRTP(pkt []byte) ([]byte, bool) {
	if hasCryptexProfile(pkt) {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fromSlab(len(pkt)+srtpMaxOverhead, func(dst []byte) ([]byte, error) {
		return c.ctx.EncryptRTP(dst, pkt, &c.rtpHdr)
	})
}

// protectRTPInto is protectRTP writing to dst, which may be pkt itself
// (in place). dst needs srtpMaxOverhead bytes of capacity past len(pkt),
// or pion allocates.
func (c *SRTPContext) protectRTPInto(dst, pkt []byte) ([]byte, bool) {
	if hasCryptexProfile(pkt) {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.ctx.EncryptRTP(dst, pkt, &c.rtpHdr)
	return out, err == nil
}

// unprotectRTP authenticates and decrypts an SRTP packet, leaving pkt
// untouched.
func (c *SRTPContext) unprotectRTP(pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fromSlab(len(pkt), func(dst []byte) ([]byte, error) {
		return c.ctx.DecryptRTP(dst, pkt, &c.rtpHdr)
	})
}

// unprotectRTPInto is unprotectRTP writing to dst, which may be pkt
// itself (in place).
func (c *SRTPContext) unprotectRTPInto(dst, pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.ctx.DecryptRTP(dst, pkt, &c.rtpHdr)
	return out, err == nil
}

// protectRTCP is protectRTP for RTCP compounds.
func (c *SRTPContext) protectRTCP(pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fromSlab(len(pkt)+srtpMaxOverhead, func(dst []byte) ([]byte, error) {
		return c.ctx.EncryptRTCP(dst, pkt, &c.rtcpHdr)
	})
}

// protectRTCPInto is protectRTPInto for RTCP compounds.
func (c *SRTPContext) protectRTCPInto(dst, pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.ctx.EncryptRTCP(dst, pkt, &c.rtcpHdr)
	return out, err == nil
}

// unprotectRTCP is unprotectRTP for SRTCP.
func (c *SRTPContext) unprotectRTCP(pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fromSlab(len(pkt), func(dst []byte) ([]byte, error) {
		return c.ctx.DecryptRTCP(dst, pkt, &c.rtcpHdr)
	})
}

// unprotectRTCPInto is unprotectRTPInto for SRTCP.
func (c *SRTPContext) unprotectRTCPInto(dst, pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.ctx.DecryptRTCP(dst, pkt, &c.rtcpHdr)
	return out, err == nil
}

// newSRTPContextFromKeys builds a context from an explicit protection
// profile and a raw master key/salt pair — the shape DTLS-SRTP produces
// (RFC 5764 §4.2), as opposed to NewSRTPContext's SDES inline value.
func newSRTPContextFromKeys(profile srtp.ProtectionProfile, masterKey, masterSalt []byte) (*SRTPContext, error) {
	keyLen, err := profile.KeyLen()
	if err != nil {
		return nil, fmt.Errorf("srtp profile: %w", err)
	}
	saltLen, err := profile.SaltLen()
	if err != nil {
		return nil, fmt.Errorf("srtp profile: %w", err)
	}
	if len(masterKey) != keyLen || len(masterSalt) != saltLen {
		return nil, fmt.Errorf("srtp key material: got %d/%d bytes, want %d/%d for this profile",
			len(masterKey), len(masterSalt), keyLen, saltLen)
	}
	return newContext(profile, masterKey, masterSalt)
}
