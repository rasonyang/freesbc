package admin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
)

// mustCfgWithSecret builds a config carrying both a peer password and an
// admin password_hash, so redactConfig has both secret kinds to strip. It is
// built directly (not via config.Parse) so an arbitrary placeholder hash can
// be used without satisfying bcrypt-format validation.
func mustCfgWithSecret(t *testing.T, peerPassword, adminPasswordHash string) *config.Config {
	t.Helper()
	return &config.Config{
		Peers: map[string]*config.Peer{
			"carrier": {
				Address:   "127.0.0.1:5060",
				Transport: "udp",
				Auth:      &config.PeerAuth{Username: "carrieruser", Password: peerPassword},
			},
		},
		Admin: &config.AdminConfig{
			Listen: "127.0.0.1:8080",
			Auth:   config.AdminAuth{Username: "admin", PasswordHash: adminPasswordHash},
		},
	}
}

func TestRedactConfig(t *testing.T) {
	cfg := mustCfgWithSecret(t, "peer-pw", "$2a$10$...adminhash...")
	v := redactConfig(cfg)
	b, _ := json.Marshal(v)
	s := string(b)
	if strings.Contains(s, "peer-pw") {
		t.Error("peer password not redacted")
	}
	if strings.Contains(s, "adminhash") {
		t.Error("admin password_hash not redacted")
	}
	// non-secret field preserved (a peer address appears)
	if !strings.Contains(s, "127.0.0.1") {
		t.Error("non-secret field lost")
	}
}

func TestRedactConfigDoesNotMutateLive(t *testing.T) {
	cfg := mustCfgWithSecret(t, "peer-pw", "$2a$10$...adminhash...")
	_ = redactConfig(cfg)
	if cfg.Peers["carrier"].Auth.Password != "peer-pw" {
		t.Error("redactConfig mutated the live config's peer password")
	}
	if cfg.Admin.Auth.PasswordHash != "$2a$10$...adminhash..." {
		t.Error("redactConfig mutated the live config's admin password hash")
	}
}
