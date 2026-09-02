package trunk

import (
	"testing"
)

func TestSelfSignedTLSConfig(t *testing.T) {
	conf, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("selfSignedTLSConfig: %v", err)
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
	// Two calls must produce independent certs (no shared global state).
	conf2, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if string(conf.Certificates[0].Certificate[0]) == string(conf2.Certificates[0].Certificate[0]) {
		t.Error("two calls produced identical certificates")
	}
}
