package media

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"time"
)

// selfSignedForTest builds a throwaway DTLS identity for the test's
// "browser" side.
func selfSignedForTest() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-browser"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// fingerprintOf renders a certificate the way SDP a=fingerprint does.
func fingerprintOf(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	hexed := hex.EncodeToString(sum[:])
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, strings.ToUpper(hexed[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// rtpPacket builds a minimal valid RTP packet with a payload of n zero
// bytes, so the relay has something realistic to carry.
func rtpPacket(pt uint8, seq uint16, payload int) []byte {
	p := make([]byte, 12+payload)
	p[0] = 0x80 // version 2
	p[1] = pt
	binary.BigEndian.PutUint16(p[2:4], seq)
	binary.BigEndian.PutUint32(p[4:8], uint32(seq)*160)
	binary.BigEndian.PutUint32(p[8:12], 0xDEADBEEF)
	return p
}
