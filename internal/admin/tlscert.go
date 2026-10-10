package admin

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// tlsExpiryWarn is how far ahead of not-after the certificate counts as
// expiring soon (the WebUI banner and expiring_soon).
const tlsExpiryWarn = 30 * 24 * time.Hour

// tlsRecord is the one top-level tls leaf the process loaded, shared by
// every listener that uses it. Only the parsed leaf is kept, never the key
// or the PEM.
type tlsRecord struct {
	leaf      *x509.Certificate
	certFile  string
	keyFile   string
	loadedAt  time.Time
	listeners []string
}

// tlsBody is the /api/tls response when a leaf is loaded. When none is, the
// response is just {"loaded": false}.
type tlsBody struct {
	Loaded bool `json:"loaded"`

	Subject     string   `json:"subject,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	KeyType     string   `json:"key_type,omitempty"`
	KeySize     int      `json:"key_size,omitempty"`
	KeyCurve    string   `json:"key_curve,omitempty"`
	Fingerprint string   `json:"fingerprint_sha256,omitempty"`
	CertFile    string   `json:"cert_file,omitempty"`
	KeyFile     string   `json:"key_file,omitempty"`
	LoadedAt    string   `json:"loaded_at,omitempty"`
	Listeners   []string `json:"listeners,omitempty"`

	// DaysToExpiry is whole days left, truncated toward zero; negative once expired,
	// 0 within a day either side of not-after (Expired tells which).
	DaysToExpiry int  `json:"days_to_expiry"`
	Expired      bool `json:"expired"`
	// ExpiringSoon is true within 30 days of not-after, expired excluded.
	ExpiringSoon bool `json:"expiring_soon"`

	// DiskDiffers is true when the first certificate in the file now on disk
	// is not the loaded leaf: renewed, restart to apply. DiskError is set
	// instead when the file cannot be read or parsed.
	DiskDiffers bool   `json:"disk_differs"`
	DiskError   string `json:"disk_error,omitempty"`
}

// fingerprint is the SHA-256 of the DER leaf as upper-case colon hex.
func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// keyInfo names the leaf's public key: type, size in bits and, for ECDSA,
// the curve.
func keyInfo(c *x509.Certificate) (typ string, bits int, curve string) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen(), ""
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize, k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519", 256, ""
	}
	return c.PublicKeyAlgorithm.String(), 0, ""
}

// expiry computes days to expiry, expired and expiring-soon at now.
func expiry(c *x509.Certificate, now time.Time) (days int, expired, soon bool) {
	left := c.NotAfter.Sub(now)
	days = int(left.Hours() / 24) // truncates toward zero
	expired = left <= 0
	return days, expired, !expired && left < tlsExpiryWarn
}

// firstCertOnDisk parses the first CERTIFICATE block of the file at path.
func firstCertOnDisk(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return nil, fmt.Errorf("no certificate in %s", path)
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

// body renders the record at now. The file is read here, on request only.
func (r *tlsRecord) body(now time.Time) tlsBody {
	c := r.leaf
	b := tlsBody{
		Loaded:      true,
		Subject:     c.Subject.CommonName,
		Issuer:      c.Issuer.String(),
		NotBefore:   c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint: fingerprint(c),
		CertFile:    r.certFile,
		KeyFile:     r.keyFile,
		LoadedAt:    r.loadedAt.UTC().Format(time.RFC3339),
		Listeners:   r.listeners,
	}
	if b.Subject == "" {
		b.Subject = c.Subject.String()
	}
	b.SANs = append(b.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		b.SANs = append(b.SANs, ip.String())
	}
	b.KeyType, b.KeySize, b.KeyCurve = keyInfo(c)
	b.DaysToExpiry, b.Expired, b.ExpiringSoon = expiry(c, now)
	if d, err := firstCertOnDisk(r.certFile); err != nil {
		b.DiskError = err.Error()
	} else {
		b.DiskDiffers = fingerprint(d) != b.Fingerprint
	}
	return b
}

// tlsRecord merges what the edge loaded (Deps.TLSCert) with what this
// server loaded for remote HTTPS. Both read the same top-level pair, so
// there is one leaf; the edge's wins when both exist. Nil when neither
// loaded it.
func (s *Server) tlsRecord() *tlsRecord {
	if s.tls == nil {
		return nil
	}
	var rec *tlsRecord
	if s.deps.TLSCert != nil {
		if leaf, at, users := s.deps.TLSCert(); leaf != nil {
			rec = &tlsRecord{leaf: leaf, loadedAt: at, listeners: users}
		}
	}
	s.tlsMu.Lock()
	own, ownAt := s.tlsLeaf, s.tlsLoaded
	s.tlsMu.Unlock()
	if own != nil {
		if rec == nil {
			rec = &tlsRecord{leaf: own, loadedAt: ownAt}
		}
		rec.listeners = append(rec.listeners, "admin")
	}
	if rec != nil {
		rec.certFile, rec.keyFile = s.tls.Cert, s.tls.Key
	}
	return rec
}

// handleTLS serves GET /api/tls: the loaded leaf with its expiry and
// whether the file on disk now differs, or {"loaded": false}.
func (s *Server) handleTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec := s.tlsRecord()
	if rec == nil {
		writeJSON(w, map[string]bool{"loaded": false})
		return
	}
	writeJSON(w, rec.body(s.clock()))
}

// healthConditions is the health tracker's source: Deps.Health plus the
// certificate expiry condition. It reads no file (the tracker also runs on a
// timer), so a renewal on disk is /api/tls's to report, not a condition.
func (s *Server) healthConditions() []HealthCondition {
	var out []HealthCondition
	if s.deps.Health != nil {
		out = s.deps.Health()
	}
	rec := s.tlsRecord()
	if rec == nil {
		return out
	}
	days, expired, soon := expiry(rec.leaf, s.clock())
	notAfter := rec.leaf.NotAfter.UTC().Format(time.RFC3339)
	switch {
	case expired:
		out = append(out, HealthCondition{
			ID:       "tls_cert_expiry",
			Severity: HealthCritical,
			Message:  "the loaded TLS certificate has expired",
			Detail:   "not after " + notAfter,
		})
	case soon:
		out = append(out, HealthCondition{
			ID:       "tls_cert_expiry",
			Severity: HealthDegraded,
			Message:  fmt.Sprintf("the loaded TLS certificate expires in %d day(s)", days),
			Detail:   "not after " + notAfter,
		})
	}
	return out
}
