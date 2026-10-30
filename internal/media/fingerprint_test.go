package media

import "testing"

// TestFingerprintWithSHA256KnownValue pins the SDP a=fingerprint format
// (RFC 8122 §5): SHA-256 over the DER, uppercase hex bytes joined by colons.
func TestFingerprintWithSHA256KnownValue(t *testing.T) {
	const want = "F2:FD:BF:1D:8E:FF:41:12:32:90:4C:32:AD:DB:CE:49:A8:1B:C9:BB:FF:46:B3:9B:42:64:FF:BA:5E:C5:79:42"
	if got := fingerprintWith("sha-256", []byte("freesbc fingerprint fixture")); got != want {
		t.Fatalf("fingerprintWith = %q, want %q", got, want)
	}
}
