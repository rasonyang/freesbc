package sip

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
)

func TestSelfSignedTLS(t *testing.T) {
	conf, err := SelfSignedTLS("freesbc-test", []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("SelfSignedTLS: %v", err)
	}
	if len(conf.Certificates) != 1 {
		t.Fatalf("want exactly 1 certificate, got %d", len(conf.Certificates))
	}
	// The certificate must be usable: a TLS server handshake path parses
	// the leaf, so a nil leaf or empty chain would be a broken config.
	if len(conf.Certificates[0].Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
	if conf.Certificates[0].PrivateKey == nil {
		t.Fatal("certificate has no private key")
	}
	if conf.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", conf.MinVersion)
	}

	leaf, err := x509.ParseCertificate(conf.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "freesbc-test" {
		t.Errorf("CN = %q", leaf.Subject.CommonName)
	}
	// Each SAN is sorted by whether it parses as an address.
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP SANs = %v", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" {
		t.Errorf("DNS SANs = %v", leaf.DNSNames)
	}

	// Two calls must produce independent certs (no shared global state).
	conf2, err := SelfSignedTLS("freesbc-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(conf.Certificates[0].Certificate[0]) == string(conf2.Certificates[0].Certificate[0]) {
		t.Error("two calls produced identical certificates")
	}
	if len(conf2.Certificates[0].Certificate) == 0 {
		t.Fatal("certificate chain is empty without SANs")
	}
}
