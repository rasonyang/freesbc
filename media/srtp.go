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
// (16-byte master key followed by a 14-byte master salt).
func NewSRTPContext(suite CryptoSuite, keyValue []byte) (*SRTPContext, error) {
	if len(keyValue) != srtpMasterKeyValueLen {
		return nil, fmt.Errorf("srtp key value must be %d bytes, got %d", srtpMasterKeyValueLen, len(keyValue))
	}
	masterKey := keyValue[:16]
	masterSalt := keyValue[16:30]
	ctx, err := srtp.CreateContext(masterKey, masterSalt, suite.profile())
	if err != nil {
		return nil, fmt.Errorf("srtp create context: %w", err)
	}
	return &SRTPContext{ctx: ctx}, nil
}

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
