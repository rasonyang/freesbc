package admin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
)

const adminHashPlaceholder = "$2a$10$...adminhash..."

func cfgWithAdminHash(t *testing.T) *config.Config {
	t.Helper()
	cfg := mustCfg(t)
	cfg.Admin = &config.AdminConfig{Listen: "127.0.0.1:8080", PasswordHash: adminHashPlaceholder}
	return cfg
}

func TestRedactConfig(t *testing.T) {
	cfg := cfgWithAdminHash(t)
	cfg.Shield.MaxSessions = 123
	cfg.Shield.InviteRateLimit = "9/s"
	cfg.Shield.RegisterBan = "7/5m"
	b, _ := json.Marshal(redactConfig(cfg))
	s := string(b)
	if strings.Contains(s, "adminhash") {
		t.Error("admin password_hash not redacted")
	}
	if !strings.Contains(s, `"password_hash":"***"`) {
		t.Errorf("password_hash not masked: %s", s)
	}
	// non-secret fields preserved
	for _, want := range []string{"203.0.113.7", "10.77.0.10:5060", "127.0.0.1:8080",
		`"max_sessions":123`, `"invite_rate_limit":"9/s"`, `"register_ban":"7/5m"`} {
		if !strings.Contains(s, want) {
			t.Errorf("non-secret value %q lost: %s", want, s)
		}
	}
}

func TestRedactConfigDoesNotMutateLive(t *testing.T) {
	cfg := cfgWithAdminHash(t)
	_ = redactConfig(cfg)
	if cfg.Admin.PasswordHash != adminHashPlaceholder {
		t.Error("redactConfig mutated the live config's admin password hash")
	}
}

// A plain carrier is shown as its host string and a mapping-form one as a
// mapping with its certificate paths.
func TestRedactConfigCarriers(t *testing.T) {
	cfg := mustCfg(t)
	cfg.Edge.Carriers = map[string]config.CarrierConfig{
		"plain":  {Host: "198.51.100.4:5060"},
		"secure": {Host: "sip.example.com", Transport: "tls", CAFile: "/etc/ca.pem", ClientCert: "/etc/c.pem", ClientKey: "/etc/c.key"},
	}
	b, _ := json.Marshal(redactConfig(cfg))
	s := string(b)
	for _, want := range []string{`"plain":"198.51.100.4:5060"`, `"transport":"tls"`, `"ca_file":"/etc/ca.pem"`, `"client_key":"/etc/c.key"`} {
		if !strings.Contains(s, want) {
			t.Errorf("%s missing from %s", want, s)
		}
	}
}

// The hep section is part of the redacted view; it holds only file paths and
// no secret.
func TestRedactConfigHEP(t *testing.T) {
	cfg := mustCfg(t)
	if b, _ := json.Marshal(redactConfig(cfg)); strings.Contains(string(b), `"hep"`) {
		t.Errorf("hep shown while off: %s", b)
	}
	f := false
	cfg.HEP = &config.HEPConfig{Address: "10.77.0.50:9061", Transport: "tls", CaptureID: 2001, NodeName: "edge1",
		RedactAuth: &f, TLS: &config.HEPTLSConfig{CA: "/etc/ca.pem", Cert: "/etc/c.pem", Key: "/etc/c.key"}}
	b, _ := json.Marshal(redactConfig(cfg))
	for _, want := range []string{`"address":"10.77.0.50:9061"`, `"capture_id":2001`, `"node_name":"edge1"`,
		`"redact_auth":false`, `"ca":"/etc/ca.pem"`, `"key":"/etc/c.key"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s missing from %s", want, b)
		}
	}
}
