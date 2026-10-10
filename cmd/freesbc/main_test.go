package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// audit: P2-APP-007
// `freesbc run other.yaml` (the path without -c) must not silently run
// ./freesbc.yaml: a positional argument is a usage error, exit 2.
func TestPositionalArgumentIsUsageError(t *testing.T) {
	dir := t.TempDir()
	// A valid ./freesbc.yaml would make the old behaviour exit 0.
	good := filepath.Join(dir, "freesbc.yaml")
	if err := os.WriteFile(good, []byte(`
public: { ip: 127.0.0.1 }
private: { ip: 192.0.2.250 }
rtp: 10010-10029
edge:
  switch: [127.0.0.1:5062]
  listen: { udp: 5060 }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"check", "-c", good, "other.yaml"},
		{"check", "other.yaml"},
		{"run", "other.yaml"},
		{"version", "x"},
		{"version", "-c", good},
	} {
		if got := run(args); got != 2 {
			t.Errorf("run(%q) = %d, want 2 (usage error)", args, got)
		}
	}
	if got := run([]string{"check", "-c", good}); got != 0 {
		t.Errorf("check -c %s = %d, want 0", good, got)
	}
}

// `freesbc version` prints one line starting with the build version and
// exits 0; the plain test build carries the default "dev".
func TestVersion(t *testing.T) {
	if got := versionLine(); !strings.HasPrefix(got, "freesbc dev go") || strings.Contains(got, "\n") {
		t.Errorf("versionLine() = %q, want one line starting with %q", got, "freesbc dev go")
	}
	if got := run([]string{"version"}); got != 0 {
		t.Errorf("run(version) = %d, want 0", got)
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

// `freesbc init` takes no positional argument and rejects unknown flags,
// like run and check, and never touches the filesystem when it does.
func TestInitArgumentHandling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freesbc.yaml")
	for _, args := range [][]string{
		{"init", "-c", path, "other.yaml"},
		{"init", "--bogus"},
		{"init", "-c", path, "--udp-port", "abc"},
	} {
		if got := run(args); got != 2 {
			t.Errorf("run(%q) = %d, want 2", args, got)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("init wrote %s on a usage error", path)
	}
	// With stdin not a terminal a missing switch is an error (exit 1), not a
	// prompt. Pin stdin so the test never prompts when run from a terminal.
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	stdin := os.Stdin
	os.Stdin = devnull
	defer func() { os.Stdin = stdin }()
	t.Setenv("FREESBC_SWITCH", "")
	if got := run([]string{"init", "-c", path, "--no-public-lookup"}); got != 1 {
		t.Errorf("init without a switch = %d, want 1", got)
	}
}
