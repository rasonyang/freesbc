package media

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// DTLSIdentity is the certificate FreeSBC presents on every browser-facing
// DTLS handshake, plus the fingerprint that certificate is bound to in
// SDP.
//
// One identity is shared by every session for the life of the process
// (spec §11): generating a key per session would put an ECDSA keygen on
// the call-setup path for no security benefit — WebRTC binds the
// certificate to the session through the a=fingerprint line carried in
// signaling, not through the certificate being unique.
type DTLSIdentity struct {
	Certificate tls.Certificate
	// FingerprintHash is the SDP hash-function token, always "sha-256".
	FingerprintHash string
	// FingerprintValue is colon-separated uppercase hex, as SDP wants it.
	FingerprintValue string
}

var (
	processIdentityOnce sync.Once
	processIdentity     *DTLSIdentity
	processIdentityErr  error
)

// ProcessDTLSIdentity returns the process-wide self-signed identity,
// generating it on first use. Concurrent callers share one certificate.
func ProcessDTLSIdentity() (*DTLSIdentity, error) {
	processIdentityOnce.Do(func() {
		processIdentity, processIdentityErr = generateDTLSIdentity()
	})
	return processIdentity, processIdentityErr
}

// LoadDTLSIdentity reads a configured certificate/key pair and derives its
// fingerprint, for deployments that want a pinned DTLS identity.
func LoadDTLSIdentity(certFile, keyFile string) (*DTLSIdentity, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("media: load dtls identity: %w", err)
	}
	return identityFrom(cert)
}

func generateDTLSIdentity() (*DTLSIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("media: dtls keygen: %w", err)
	}
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, fmt.Errorf("media: dtls serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "FreeSBC"},
		NotBefore:    time.Now().Add(-time.Hour),
		// A year: long enough that a long-lived process never serves an
		// expired certificate, short enough to stay unremarkable. Nothing
		// verifies this chain — WebRTC trusts the fingerprint in SDP — so
		// the validity window is hygiene, not a control.
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("media: dtls certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("media: dtls certificate parse: %w", err)
	}
	return identityFrom(tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	})
}

func identityFrom(cert tls.Certificate) (*DTLSIdentity, error) {
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("media: dtls identity has no certificate")
	}
	// RFC 8122 §5: the fingerprint is over the DER of the certificate,
	// rendered as uppercase hex bytes joined by colons.
	sum := sha256.Sum256(cert.Certificate[0])
	hexed := hex.EncodeToString(sum[:])
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, strings.ToUpper(hexed[i:i+2]))
	}
	if cert.Leaf == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			cert.Leaf = leaf
		}
	}
	return &DTLSIdentity{
		Certificate:      cert,
		FingerprintHash:  "sha-256",
		FingerprintValue: strings.Join(parts, ":"),
	}, nil
}
