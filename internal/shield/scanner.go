// Package shield is FreeSBC's front-door security plane: per-IP rate limiting,
// scanner fingerprinting, and an in-memory ban list. Every inbound SIP
// request passes Shield.Check before identification; denials are silent drops.
package shield

import "strings"

// scannerSignatures are lowercased substrings of User-Agent values used by
// well-known SIP scanning/attack tools. Deliberately specific — no bare
// "scanner" substring that could match a legitimate product.
var scannerSignatures = []string{
	"friendly-scanner", // sipvicious default
	"sipvicious",
	"sipcli",
	"sip-scan",
	"sundayddr",
	"vaxsipuseragent",
	"sipsak",
	"iwar",
	"sivus",
	"smap",
	"pplsip",
}

// isScanner reports whether ua contains a known scanner signature
// (case-insensitive). An empty UA is not a match.
func isScanner(ua string) bool {
	if ua == "" {
		return false
	}
	lower := strings.ToLower(ua)
	for _, sig := range scannerSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}
