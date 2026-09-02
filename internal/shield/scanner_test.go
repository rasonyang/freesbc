package shield

import "testing"

func TestIsScannerMatchesKnownTools(t *testing.T) {
	scanners := []string{
		"friendly-scanner",
		"friendly-scanner",
		"sipvicious",
		"SIPVicious",                      // case-insensitive
		"Test Agent friendly-scanner/1.0", // substring
		"sipcli/v1.8",
		"VaxSIPUserAgent/1.0",
	}
	for _, ua := range scanners {
		if !isScanner(ua) {
			t.Errorf("isScanner(%q) = false, want true", ua)
		}
	}
}

func TestIsScannerAllowsLegitAndEmpty(t *testing.T) {
	legit := []string{
		"",                          // absent UA
		"Z 5.5.14 rv2.10.16.5",      // Zoiper
		"Grandstream GXP2140 1.0.9", // desk phone
		"FreeSWITCH-mod_sofia/1.10", // softswitch
		"pjsua v2.10",               // pjsip
	}
	for _, ua := range legit {
		if isScanner(ua) {
			t.Errorf("isScanner(%q) = true, want false (legit UA misflagged)", ua)
		}
	}
}
