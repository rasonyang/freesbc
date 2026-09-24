package media

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for production paths the rest of the suite never reached
// (audit P1-010).

// TestLoadDTLSIdentity covers the pinned-identity path that
// webrtc.dtls_cert_file/dtls_key_file select: the loaded certificate must
// be the one on disk and its fingerprint must be SHA-256 over that DER.
func TestLoadDTLSIdentity(t *testing.T) {
	gen, err := generateDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(gen.Certificate.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "dtls.crt")
	keyFile := filepath.Join(dir, "dtls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gen.Certificate.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := LoadDTLSIdentity(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadDTLSIdentity: %v", err)
	}
	if id.FingerprintHash != "sha-256" {
		t.Errorf("FingerprintHash = %q, want sha-256", id.FingerprintHash)
	}
	sum := sha256.Sum256(gen.Certificate.Certificate[0])
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	if got := strings.ReplaceAll(id.FingerprintValue, ":", ""); got != want {
		t.Errorf("fingerprint %s does not match the certificate on disk", id.FingerprintValue)
	}
	if id.FingerprintValue != gen.FingerprintValue {
		t.Errorf("loaded fingerprint %s != generated %s", id.FingerprintValue, gen.FingerprintValue)
	}
	if id.Certificate.Leaf == nil {
		t.Error("loaded identity has no parsed leaf")
	}

	if _, err := LoadDTLSIdentity(filepath.Join(dir, "missing.crt"), keyFile); err == nil {
		t.Error("a missing certificate file must be an error")
	}
	if _, err := LoadDTLSIdentity(keyFile, certFile); err == nil {
		t.Error("swapped certificate and key files must be an error")
	}
}

// TestSetRTCPRemoteOverridesOnlyRTCP covers the a=rtcp override: it moves
// the RTCP destination of one side and leaves that side's RTP destination
// and the other side alone.
func TestSetRTCPRemoteOverridesOnlyRTCP(t *testing.T) {
	s := &Session{}
	for side := range s.rtp {
		s.rtp[side] = &latch{mode: LatchLoose}
		s.rtcp[side] = &latch{mode: LatchLoose}
	}
	s.SetRemote(SideA, netip.MustParseAddrPort("192.0.2.10:4000"))
	s.SetRemote(SideB, netip.MustParseAddrPort("192.0.2.20:6000"))

	s.SetRTCPRemote(SideA, netip.MustParseAddrPort("192.0.2.10:4999"))

	if got := s.rtcp[SideA].target(); got == nil || got.Port != 4999 || got.IP.String() != "192.0.2.10" {
		t.Errorf("side A RTCP target = %v, want 192.0.2.10:4999", got)
	}
	if got := s.rtp[SideA].target(); got == nil || got.Port != 4000 {
		t.Errorf("side A RTP target = %v, want it unchanged at :4000", got)
	}
	if got := s.rtcp[SideB].target(); got == nil || got.Port != 6001 {
		t.Errorf("side B RTCP target = %v, want the RTP+1 default :6001", got)
	}
}
