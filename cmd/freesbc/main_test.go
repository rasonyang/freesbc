package main

import (
	"os"
	"path/filepath"
	"testing"
)

// audit: P2-APP-007
// `freesbc run edge.yaml` (the path without -c) must not silently run
// ./sbc.yaml: a positional argument is a usage error, exit 2.
func TestPositionalArgumentIsUsageError(t *testing.T) {
	dir := t.TempDir()
	// A valid ./sbc.yaml would make the old behaviour exit 0.
	good := filepath.Join(dir, "sbc.yaml")
	if err := os.WriteFile(good, []byte(`
listen: { sip: [udp://127.0.0.1:5060] }
peers:
  p: { address: 10.0.0.1:5060, allowed_ips: [10.0.0.0/8] }
routes:
  - { name: r, from: p, to: [p] }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"check", "-c", good, "edge.yaml"},
		{"check", "edge.yaml"},
		{"run", "edge.yaml"},
	} {
		if got := run(args); got != 2 {
			t.Errorf("run(%q) = %d, want 2 (usage error)", args, got)
		}
	}
	if got := run([]string{"check", "-c", good}); got != 0 {
		t.Errorf("check -c %s = %d, want 0", good, got)
	}
}
