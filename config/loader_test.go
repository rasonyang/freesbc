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

func TestParseEnvVarInCommentIsIgnored(t *testing.T) {
	src := minimalYAML + "# retired peer, was using ${SOME_UNSET_VAR}\n"
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatalf("comment referencing an unset var must not fail parsing: %v", err)
	}
}

func TestParseEnvExpansionPreservesQuotesAndNewlines(t *testing.T) {
	t.Setenv("TEST_SBC_QUOTED", `has "quotes" inside`)
	t.Setenv("TEST_SBC_MULTILINE", "line one\nline two")

	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${TEST_SBC_QUOTED}\" }", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := c.Peers["pbx"].Auth.Password, `has "quotes" inside`; got != want {
		t.Errorf("password = %q, want %q", got, want)
	}

	src2 := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${TEST_SBC_MULTILINE}\" }", 1)
	c2, err := Parse([]byte(src2))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := c2.Peers["pbx"].Auth.Password, "line one\nline two"; got != want {
		t.Errorf("password = %q, want %q", got, want)
	}
}

func TestParseErrorDoesNotLeakSecret(t *testing.T) {
	t.Setenv("TEST_SBC_SECRET", "SUPERSECRET_SENTINEL")
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${TEST_SBC_SECRET}\" }", 1)
	// Introduce a strict-mode parse error (unknown key) alongside the secret reference.
	src += "bogus_key: true\n"
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("expected parse error")
	}
	if strings.Contains(err.Error(), "SUPERSECRET_SENTINEL") {
		t.Errorf("parse error must not leak the secret value: %q", err.Error())
	}
}

func TestParseMalformedEnvRefFails(t *testing.T) {
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${TEST_SBC_UNSET_VAR:-default}\" }", 1)
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("expected error for bash-style ${VAR:-default} reference")
	}
	if strings.Contains(err.Error(), "undefined environment variable") {
		t.Errorf("malformed reference should not be reported as a missing variable: %v", err)
	}
}

func TestParseMissingEnvVarNamedOnce(t *testing.T) {
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: \"${TEST_SBC_DUP_UNSET}\", password: \"${TEST_SBC_DUP_UNSET}\" }", 1)
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("expected missing-env error")
	}
	if n := strings.Count(err.Error(), "TEST_SBC_DUP_UNSET"); n != 1 {
		t.Errorf("expected variable named once in error, got %d times: %q", n, err.Error())
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
