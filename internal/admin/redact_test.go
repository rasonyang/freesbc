package admin

import (
	"encoding/json"
	"reflect"
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

// Every yaml key of config.Config must appear in the view, so a key added to
// the schema and forgotten in redactConfig fails here. Every optional section
// is populated so the walk sees it; password_hash must be present but masked.
func TestRedactConfigCoversSchema(t *testing.T) {
	cfg := cfgWithAdminHash(t)
	cfg.TLS = &config.TLSConfig{Cert: "/etc/cert.pem", Key: "/etc/key.pem"}
	cfg.Edge.Carriers = map[string]config.CarrierConfig{
		"secure": {Host: "sip.example.com", Transport: "tls", SRTP: "optional",
			CAFile: "/etc/ca.pem", ClientCert: "/etc/c.pem", ClientKey: "/etc/c.key"},
	}
	cfg.Admin.AllowedHosts = []string{"sbc.example.com"}
	cfg.Admin.Pprof = true
	redact := true
	cfg.HEP = &config.HEPConfig{Address: "192.0.2.9:9060", Transport: "tls", CaptureID: 7, NodeName: "edge1",
		RedactAuth: &redact, TLS: &config.HEPTLSConfig{CA: "/etc/ca.pem", Cert: "/etc/c.pem", Key: "/etc/c.key"}}
	b, err := json.Marshal(redactConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var view any
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatal(err)
	}
	checkViewKeys(t, reflect.TypeOf(config.Config{}), view, "")
	admin := view.(map[string]any)["admin"].(map[string]any)
	if admin["password_hash"] != "***" {
		t.Errorf("admin.password_hash = %v, want masked", admin["password_hash"])
	}
}

// checkViewKeys walks typ's yaml tags beside the decoded JSON view v.
func checkViewKeys(t *testing.T, typ reflect.Type, v any, path string) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			t.Errorf("%s: view is %T, want an object", path, v)
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if key == "" || key == "-" {
				continue
			}
			child, ok := m[key]
			if !ok {
				t.Errorf("config key %s%s missing from the /api/config view", path, key)
				continue
			}
			checkViewKeys(t, f.Type, child, path+key+".")
		}
	case reflect.Map:
		if typ.Elem().Kind() != reflect.Struct {
			return
		}
		m, ok := v.(map[string]any)
		if !ok {
			t.Errorf("%s: view is %T, want an object", path, v)
			return
		}
		for name, child := range m {
			checkViewKeys(t, typ.Elem(), child, path+name+".")
		}
	case reflect.Slice:
		if typ.Elem().Kind() != reflect.Struct {
			return
		}
		items, _ := v.([]any)
		for _, child := range items {
			checkViewKeys(t, typ.Elem(), child, path)
		}
	}
}
