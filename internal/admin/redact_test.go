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
		`"max_sessions":123`, `"invite_rate_limit":"9/s"`} {
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
