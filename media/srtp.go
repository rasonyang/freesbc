package media

import (
	"fmt"
	"sync"

	"github.com/pion/srtp/v3"
)

// srtpMasterKeyValueLen is the length of a SDES inline value for the
// AES_CM_128 suites: a 16-byte master key concatenated with a 14-byte master
// salt.
const srtpMasterKeyValueLen = 30

// SrtpMasterKeyValueLen is the SDES inline value length (key‖salt) for the
// supported suites, exported so the signaling package can validate keys.
func SrtpMasterKeyValueLen() int { return srtpMasterKeyValueLen }

// CryptoSuite identifies an SDES/SRTP crypto suite. Only the two AES_CM_128
// suites are supported (spec §1.3).
type CryptoSuite int

const (
	SuiteAES128CM80 CryptoSuite = iota // AES_CM_128_HMAC_SHA1_80
	SuiteAES128CM32                    // AES_CM_128_HMAC_SHA1_32
)

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
type SRTPContext struct {
	mu  sync.Mutex
	ctx *srtp.Context
}

// NewSRTPContext builds a context from a 30-byte SDES inline value
// (16-byte master key followed by a 14-byte master salt), with replay
// protection enabled (T-08/F-09, RFC 3711 §3.3.2/§3.4.2 MUST): a
// replayed/too-old packet fails unprotect and is dropped by the relay's
// existing fail-closed path — pion's default is no replay protection, which
// would let a captured valid packet be re-injected indefinitely. The
// windows are per-context (one context protects exactly one stream of one
// direction), so they don't interact across legs or sides.
func NewSRTPContext(suite CryptoSuite, keyValue []byte) (*SRTPContext, error) {
	if len(keyValue) != srtpMasterKeyValueLen {
		return nil, fmt.Errorf("srtp key value must be %d bytes, got %d", srtpMasterKeyValueLen, len(keyValue))
	}
	masterKey := keyValue[:16]
	masterSalt := keyValue[16:30]
	ctx, err := srtp.CreateContext(masterKey, masterSalt, suite.profile(),
		srtp.SRTPReplayProtection(srtpReplayWindow),
		srtp.SRTCPReplayProtection(srtcpReplayWindow))
	if err != nil {
		return nil, fmt.Errorf("srtp create context: %w", err)
	}
	return &SRTPContext{ctx: ctx}, nil
}

// srtpReplayWindow and srtcpReplayWindow are the replay-protection window
// sizes passed to pion (T-08/F-09). 64 covers any plausible jitter/out-of-
// order arrival on a single media stream; RTCP gets 128 since its
// compounds are rarer and arrive more irregularly. Both bound the index
// space a replayer can claim: anything older than the window (or already
// seen) fails authentication.
const (
	srtpReplayWindow  = 64
	srtcpReplayWindow = 128
)

// protectRTP encrypts a plaintext RTP packet in place-ish (pion allocates the
// output). ok=false on failure (the caller drops the packet).
func (c *SRTPContext) protectRTP(pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.ctx.EncryptRTP(nil, pkt, nil)
	return out, err == nil
}

func (c *SRTPContext) unprotectRTP(pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.ctx.DecryptRTP(nil, pkt, nil)
	return out, err == nil
}

func (c *SRTPContext) protectRTCP(pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.ctx.EncryptRTCP(nil, pkt, nil)
	return out, err == nil
}

func (c *SRTPContext) unprotectRTCP(pkt []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.ctx.DecryptRTCP(nil, pkt, nil)
	return out, err == nil
}

// NewSRTPContextFromKeys builds a context from an explicit protection
// profile and a raw master key/salt pair — the shape DTLS-SRTP produces
// (RFC 5764 §4.2), as opposed to NewSRTPContext's SDES inline value.
//
// Replay protection is enabled exactly as it is for SDES: pion defaults to
// none, which would let a captured packet be re-injected indefinitely.
func NewSRTPContextFromKeys(profile srtp.ProtectionProfile, masterKey, masterSalt []byte) (*SRTPContext, error) {
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
	ctx, err := srtp.CreateContext(masterKey, masterSalt, profile,
		srtp.SRTPReplayProtection(srtpReplayWindow),
		srtp.SRTCPReplayProtection(srtcpReplayWindow))
	if err != nil {
		return nil, fmt.Errorf("srtp create context: %w", err)
	}
	return &SRTPContext{ctx: ctx}, nil
}

// ProtectRTP and UnprotectRTP expose the SRTP transforms to callers
// outside the relay's own forward loop (the WebRTC leg, which owns its
// packet path). The unexported lowercase forms stay the relay's API.
func (c *SRTPContext) ProtectRTP(pkt []byte) ([]byte, bool)   { return c.protectRTP(pkt) }
func (c *SRTPContext) UnprotectRTP(pkt []byte) ([]byte, bool) { return c.unprotectRTP(pkt) }

// ProtectRTCP and UnprotectRTCP are the RTCP counterparts.
func (c *SRTPContext) ProtectRTCP(pkt []byte) ([]byte, bool)   { return c.protectRTCP(pkt) }
func (c *SRTPContext) UnprotectRTCP(pkt []byte) ([]byte, bool) { return c.unprotectRTCP(pkt) }
