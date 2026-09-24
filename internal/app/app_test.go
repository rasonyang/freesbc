package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// appMediaPortMin..appMediaPortMax is this package's slice of the test
// port map (CLAUDE.md, "Test ports"). The trunk plane binds media ports
// only per call, and this test places none, but the range still has to be
// valid and must not overlap another package's.
const (
	appMediaPortMin = 10000
	appMediaPortMax = 10009
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

// TestRunStartsAndStopsOnCancel starts the trunk plane on a real port,
// proves it is actually serving (a peer's OPTIONS is answered), and checks
// that cancelling the context is a clean shutdown (nil error) that releases
// the listener.
//
// It used to sleep 200 ms and cancel, which passed just as well when the
// listener had not bound yet: it never showed that startup succeeded.
//
// audit: P2-APP-009
func TestRunStartsAndStopsOnCancel(t *testing.T) {
	// The SIP port comes from the kernel and is closed again before Run
	// binds it, so another socket can take it in between. That shows up as
	// a bind error from Run before the server answers; retry on fresh
	// ports rather than flake.
	for attempt := 1; ; attempt++ {
		sipPort, peerPort := freeUDPPort(t), freeUDPPort(t)
		done, cancel := startRun(t, sipPort, peerPort)
		err := waitServing(sipPort, done)
		if err != nil {
			cancel()
			if isAddrInUse(err) && attempt < 3 {
				t.Logf("attempt %d: %v; retrying on fresh ports", attempt, err)
				continue
			}
			t.Fatalf("trunk plane never served: %v", err)
		}

		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Run after cancel = %v, want nil", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return after ctx cancel")
		}

		// A clean shutdown gives the port back.
		c, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", sipPort))
		if err != nil {
			t.Fatalf("SIP port %d still bound after Run returned: %v", sipPort, err)
		}
		_ = c.Close()
		return
	}
}

// startRun runs the process with a one-peer trunk config on sipPort.
// Run's result arrives on done; the returned cancel stops it.
func startRun(t *testing.T, sipPort, peerPort int) (<-chan error, context.CancelFunc) {
	t.Helper()
	path := writeConfig(t, fmt.Sprintf(`
listen:
  sip:
    - udp://127.0.0.1:%d
  media:
    port_range: %d-%d
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
`, sipPort, appMediaPortMin, appMediaPortMax, peerPort))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			ConfigPath: path,
			Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			Version:    "test",
		})
	}()
	return done, cancel
}

// waitServing polls the trunk listener with OPTIONS from 127.0.0.1, an
// allowed peer source, until it answers 200. It fails fast if Run returns
// first — which is how a bind error surfaces.
func waitServing(sipPort int, done <-chan error) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sipPort}
	local := conn.LocalAddr().String()
	buf := make([]byte, 4096)
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("Run returned nil before serving")
			}
			return err
		default:
		}
		req := strings.Join([]string{
			fmt.Sprintf("OPTIONS sip:sbc@127.0.0.1:%d SIP/2.0", sipPort),
			fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-app-ready-%d", local, i),
			"From: <sip:probe@127.0.0.1>;tag=probe",
			"To: <sip:sbc@127.0.0.1>",
			fmt.Sprintf("Call-ID: app-ready-%d", i),
			"CSeq: 1 OPTIONS",
			"Max-Forwards: 70",
			"Content-Length: 0",
			"", "",
		}, "\r\n")
		if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil && strings.HasPrefix(string(buf[:n]), "SIP/2.0 200") {
			return nil
		}
	}
	return errors.New("no 200 to OPTIONS within 10s")
}

// isAddrInUse reports a bind collision. The string check covers a layer
// that formats the bind error with %v instead of wrapping it.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use")
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// freeUDPPort returns a port the kernel just handed out and closed again.
// Another socket can take it before the caller binds it, so callers must
// treat a bind failure as retryable (see TestRunStartsAndStopsOnCancel).
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
