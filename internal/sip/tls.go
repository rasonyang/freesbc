package sip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"
)

// SelfSignedTLS builds a TLS config backed by a freshly generated,
// in-memory, self-signed ECDSA certificate, for a TLS or WSS listener that
// was configured without one.
//
// It exists so a missing certificate file degrades to a listener that
// binds and logs loudly, rather than taking the whole process down at
// startup. It is NOT a usable deployment posture: nothing will trust the
// certificate, and a browser refuses a WSS connection outright because
// there is no way to click through a certificate warning on a WebSocket
// opened by script.
//
// cn is the subject common name and sans the subject alternative names,
// each sorted into the IP or the DNS list by whether it parses as an
// address. The key is never persisted and every call mints a new
// certificate, so the validity is one year: a process that outlives it has
// long since been given a real certificate.
func SelfSignedTLS(cn string, sans []string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, s := range sans {
		if ip, err := netip.ParseAddr(s); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, s)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        leaf,
		}},
		MinVersion: tls.VersionTLS12,
	}, nil
}
