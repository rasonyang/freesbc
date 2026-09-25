package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if c.Shield.AutoBan.Duration.Std() != time.Hour {
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

// audit: P2-SHD-004
// The nftables backend and the unidentified-source auto-ban counter are
// gone, so their keys are unknown fields: a config that still sets them is
// rejected rather than silently ignored.
func TestParseRejectsRemovedShieldKeys(t *testing.T) {
	for _, key := range []string{
		"shield:\n  nftables: auto\n",
		"shield:\n  auto_ban: { failures: 5 }\n",
		"shield:\n  auto_ban: { window: 60s }\n",
	} {
		_, err := Parse([]byte(minimalYAML + key))
		if err == nil {
			t.Errorf("%q: removed shield key accepted", key)
		}
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

func TestParseQuotedScalars(t *testing.T) {
	src := `
listen:
  sip: ["udp://0.0.0.0:5060"]
  media:
    port_range: "16384-32768"
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: pbx
    to: [pbx]
shield:
  auto_ban: { duration: "60s" }
`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("quoted scalars must parse: %v", err)
	}
	if c.Listen.SIP[0].Port != 5060 {
		t.Errorf("listener: %+v", c.Listen.SIP[0])
	}
	if c.Listen.Media.PortRange.Min != 16384 {
		t.Errorf("port range: %+v", c.Listen.Media.PortRange)
	}
	if c.Shield.AutoBan.Duration.Std() != 60*time.Second {
		t.Errorf("duration: %v", c.Shield.AutoBan.Duration.Std())
	}
}

func TestParseNumericBraceRefIsLiteral(t *testing.T) {
	// ${1} is a regexp capture-group reference, not an env var (a digit-led
	// name is never a valid env variable), so it must survive parsing
	// verbatim — routing transforms depend on this.
	src := strings.Replace(minimalYAML, "from: pbx",
		"from: pbx\n    match: { to: \"^9(\\\\d+)$\" }\n    transform: { to: \"00${1}\" }", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("${1} in a transform must parse, got: %v", err)
	}
	if got := c.Routes[0].Transform.To; got != "00${1}" {
		t.Errorf("transform.to = %q, want literal \"00${1}\"", got)
	}
}

func TestParseMalformedRefStillRejected(t *testing.T) {
	// A bash-style default is still malformed and must still be rejected —
	// the numeric-group carve-out must not weaken this.
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${PASS:-x}\" }", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected malformed-ref error, got: %v", err)
	}
}

func TestParseDigitLedNonNumericRefStillMalformed(t *testing.T) {
	// The ${N} carve-out is ONLY for pure-digit spans. Digit-led spans that
	// aren't pure digits are still malformed and must stay rejected.
	for _, bad := range []string{"${1abc}", "${1:-x}"} {
		src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
			"address: 10.0.0.10:5060\n    auth: { username: u, password: \""+bad+"\" }", 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Errorf("%q must be rejected as malformed, got: %v", bad, err)
		}
	}
}

// audit: P2-CFG-001
// A null upstream node is rejected up front with a message naming it, like
// the other null map/list entries, instead of being left to later steps.
func TestParseRejectsNullUpstreamNode(t *testing.T) {
	src := strings.Replace(proxyYAML, "  upstream:\n    address: 10.77.0.10:5060\n    transport: udp\n",
		"  upstreams:\n    nodes:\n      fs-a:\n", 1)
	_, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "sip.upstreams.nodes.fs-a: empty entry (null)") {
		t.Fatalf("want a null-entry error for fs-a, got %v", err)
	}
}
