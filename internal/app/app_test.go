package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/edge"
)

// edgeRunYAML is a v2 config for Run tests: public UDP on pubPort at
// 127.0.0.1, the switch at 127.0.0.1:upPort (never contacted before a call
// arrives). private.ip is a non-local placeholder: tests override the fixed
// private socket with edge.WithPrivateAddr (see setPrivate). The RTP range
// sits in this package's slice of the test port map (CLAUDE.md, "Test
// ports").
func edgeRunYAML(pubPort, upPort int) string {
	return fmt.Sprintf(`
public: { ip: 127.0.0.1 }
private: { ip: 192.0.2.250 }
rtp: 10010-10029
edge:
  switch: [127.0.0.1:%d]
  listen: { udp: %d }
`, upPort, pubPort)
}

// setPrivate points the edge's private socket at 127.0.0.1:port for the
// rest of the test.
func setPrivate(t *testing.T, port int) {
	t.Helper()
	testHookEdgeOptions = []edge.Option{edge.WithPrivateAddr(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)))}
	t.Cleanup(func() { testHookEdgeOptions = nil })
}

// TestCheckExamples is the guard on the shipped example: it must keep
// loading and validating exactly as `freesbc check` runs it.
func TestCheckExamples(t *testing.T) {
	if _, err := Check(filepath.Join("..", "..", "freesbc.example.yaml")); err != nil {
		t.Errorf("Check(freesbc.example.yaml): %v", err)
	}
	if _, err := Check(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("Check on a missing file must fail")
	}
}

// TestRunStartsAndStopsOnCancel starts the edge plane on a real port,
// proves it is actually serving (a dialog-less BYE to the public listener is answered 481), and checks
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
		sipPort, privPort, upPort := freeUDPPort(t), freeUDPPort(t), freeUDPPort(t)
		setPrivate(t, privPort)
		done, cancel := startRun(t, sipPort, upPort)
		err := waitServing(sipPort, done)
		if err != nil {
			cancel()
			if isAddrInUse(err) && attempt < 3 {
				t.Logf("attempt %d: %v; retrying on fresh ports", attempt, err)
				continue
			}
			t.Fatalf("edge plane never served: %v", err)
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

// startRun runs the process with an edge-only config on sipPort.
// Run's result arrives on done; the returned cancel stops it.
func startRun(t *testing.T, sipPort, upPort int) (<-chan error, context.CancelFunc) {
	t.Helper()
	path := writeConfig(t, edgeRunYAML(sipPort, upPort))

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

// waitServing polls the public listener from 127.0.0.1 until it answers (a BYE naming no
// dialog gets 481 from the edge itself; a public OPTIONS from an unregistered
// source is dropped silently since #188). It fails fast if Run returns
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
			fmt.Sprintf("BYE sip:sbc@127.0.0.1:%d SIP/2.0", sipPort),
			fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-app-ready-%d", local, i),
			"From: <sip:probe@127.0.0.1>;tag=probe",
			"To: <sip:sbc@127.0.0.1>;tag=probe-to",
			fmt.Sprintf("Call-ID: app-ready-%d", i),
			"CSeq: 1 BYE",
			"Max-Forwards: 70",
			"Content-Length: 0",
			"", "",
		}, "\r\n")
		if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil && strings.HasPrefix(string(buf[:n]), "SIP/2.0 481") {
			return nil
		}
	}
	return errors.New("no 481 to BYE within 10s")
}

// isAddrInUse reports a bind collision. The string check covers a layer
// that formats the bind error with %v instead of wrapping it.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use")
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "freesbc.yaml")
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

// check hands back the NAT checklist for a public.bind != public.ip config
// and nothing otherwise.
func TestCheckNATNote(t *testing.T) {
	write := func(extra string) string {
		p := filepath.Join(t.TempDir(), "c.yaml")
		src := "public: { ip: 203.0.113.7" + extra + " }\nprivate: { ip: 10.77.0.2 }\nedge:\n  switch: [10.77.0.10:5060]\n  listen: { udp: 5060 }\n"
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	note, err := Check(write(", bind: 172.20.0.4"))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"NAT mode: advertised public endpoint = 203.0.113.7", "REQUIRED forwards -> 172.20.0.4", "udp/5060", "(rtp)"} {
		if !strings.Contains(note, w) {
			t.Errorf("note lacks %q:\n%s", w, note)
		}
	}
	if note, err := Check(write("")); err != nil || note != "" {
		t.Errorf("non-NAT Check = %q, %v; want empty note", note, err)
	}
}
