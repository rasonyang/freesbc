package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

// audit: P2-APP-008
// The first SIGINT starts a graceful shutdown; a second one must end the
// process even when that shutdown hangs. The hang runs in a child copy of
// this test binary (FREESBC_TEST_HUNG_SHUTDOWN), which the test signals
// twice.
func TestSecondSignalForcesExit(t *testing.T) {
	if os.Getenv("FREESBC_TEST_HUNG_SHUTDOWN") == "1" {
		_ = withSignals(func(ctx context.Context) error {
			fmt.Println("ready")
			<-ctx.Done()
			fmt.Println("shutting down")
			select {} // a shutdown that never finishes
		})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecondSignalForcesExit$")
	cmd.Env = append(os.Environ(), "FREESBC_TEST_HUNG_SHUTDOWN=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(out)
	waitLine := func(want string) {
		t.Helper()
		for lines.Scan() {
			if lines.Text() == want {
				return
			}
		}
		t.Fatalf("child never printed %q", want)
	}
	done := make(chan error, 1)
	waitLine("ready")
	_ = cmd.Process.Signal(syscall.SIGINT)
	waitLine("shutting down")
	go func() { done <- cmd.Wait() }()
	// Keep signalling: the child releases signal capture on its own
	// goroutine, so the first of these may still be captured.
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-done:
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("child exited with %v, want death by SIGINT", err)
			}
			return
		case <-tick.C:
			_ = cmd.Process.Signal(syscall.SIGINT)
		case <-deadline:
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("further SIGINTs did not end a hung shutdown")
		}
	}
}
