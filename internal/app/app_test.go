package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCheckExamples is the guard on the shipped examples: both must keep
// loading and validating exactly as `freesbc check` runs them.
func TestCheckExamples(t *testing.T) {
	t.Setenv("CARRIER_A_PASS", "x")
	for _, name := range []string{"sbc.example.yaml", "edge.example.yaml"} {
		if err := Check(filepath.Join("..", "..", name)); err != nil {
			t.Errorf("Check(%s): %v", name, err)
		}
	}
	if err := Check(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("Check on a missing file must fail")
	}
}

// TestRunStartsAndStopsOnCancel starts the trunk plane on a real port and
// checks that cancelling the context is a clean shutdown (nil error).
func TestRunStartsAndStopsOnCancel(t *testing.T) {
	path := writeConfig(t, fmt.Sprintf(`
listen:
  sip:
    - udp://127.0.0.1:%d
  media:
    port_range: 41100-41110
    public_ip: 127.0.0.1
peers:
  p1:
    address: 127.0.0.1:%d
    transport: udp
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r1
    from: p1
    to: [p1]
`, freeUDPPort(t), freeUDPPort(t)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			ConfigPath: path,
			Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			Version:    "test",
		})
	}()

	// Give the listeners a moment to bind, then ask for shutdown.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// freeUDPPort returns a port the kernel just handed out and closed again —
// good enough for a test that binds it immediately afterwards.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}
