package config

import (
	"strings"
	"testing"
)

// edge.allow_register_auth_mismatch parses, defaults to false and is not
// accepted as anything but a bool.
func TestAllowRegisterAuthMismatchConfig(t *testing.T) {
	if mustParse(t, minimalYAML).Edge.AllowRegisterAuthMismatch {
		t.Error("allow_register_auth_mismatch defaults to true, want false")
	}
	on := strings.Replace(minimalYAML, "edge:\n", "edge:\n  allow_register_auth_mismatch: true\n", 1)
	if !mustParse(t, on).Edge.AllowRegisterAuthMismatch {
		t.Error("allow_register_auth_mismatch: true did not parse")
	}
	bad := strings.Replace(minimalYAML, "edge:\n", "edge:\n  allow_register_auth_mismatch: maybe\n", 1)
	if _, err := Parse([]byte(bad)); err == nil {
		t.Error("a non-bool value was accepted")
	}
}
