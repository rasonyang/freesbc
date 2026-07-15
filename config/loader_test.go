package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalYAML = `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: pbx
    to: [pbx]
`

func TestParseMinimal(t *testing.T) {
	c, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Peers["pbx"].Transport != "udp" {
		t.Error("defaults not applied")
	}
	if c.Shield.NFTables != "auto" {
		t.Error("shield defaults not applied")
	}
}

func TestParseUnknownFieldRejectedWithLine(t *testing.T) {
	src := minimalYAML + "bogus_key: true\n"
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("expected unknown-field error")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Errorf("error should name the unknown key: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "line") && !strings.Contains(err.Error(), "12") {
		t.Errorf("error should carry position info: %q", err.Error())
	}
}

func TestParseEnvExpansion(t *testing.T) {
	t.Setenv("TEST_SBC_PASS", "s3cret")
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${TEST_SBC_PASS}\" }", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c.Peers["pbx"].Auth.Password; got != "s3cret" {
		t.Errorf("password = %q, want expanded env value", got)
	}
}

func TestParseMissingEnvVarFails(t *testing.T) {
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${TEST_SBC_UNSET_VAR}\" }", 1)
	_, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "TEST_SBC_UNSET_VAR") {
		t.Errorf("expected missing-env error naming the variable, got: %v", err)
	}
}

func TestParseInvalidConfigFails(t *testing.T) {
	src := strings.Replace(minimalYAML, "from: pbx", "from: ghost", 1)
	_, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}
