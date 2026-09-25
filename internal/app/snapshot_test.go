package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/freesbc/freesbc/internal/config"
)

// freeTCPPort returns a loopback TCP port the kernel just handed out and
// closed again (see freeUDPPort for the caveat).
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// audit: P2-APP-004
// Run makes every startup decision from the snapshot it loaded. A reload
// that lands after the watcher starts (here: one that drops the admin
// section) must not change what this startup builds: the admin API the
// file asked for still comes up.
func TestRunStartsFromOneSnapshot(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), 10)
	if err != nil {
		t.Fatal(err)
	}
	sipPort, peerPort, adminPort := freeUDPPort(t), freeUDPPort(t), freeTCPPort(t)
	trunk := fmt.Sprintf(`
listen:
  sip: [udp://127.0.0.1:%d]
  media: { port_range: %d-%d, public_ip: 127.0.0.1 }
peers:
  p1: { address: 127.0.0.1:%d, allowed_ips: [127.0.0.1/32] }
routes:
  - { name: r1, from: p1, to: [p1] }
`, sipPort, appMediaPortMin, appMediaPortMax, peerPort)
	withAdmin := trunk + fmt.Sprintf(`
admin:
  listen: 127.0.0.1:%d
  auth: { username: admin, password_hash: %q }
`, adminPort, hash)
	noAdmin, err := config.Parse([]byte(trunk))
	if err != nil {
		t.Fatal(err)
	}
	testHookWatchStarted = func(s *config.Store) { s.Replace(noAdmin) }
	t.Cleanup(func() { testHookWatchStarted = nil })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{ConfigPath: writeConfig(t, withAdmin), Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	if err := waitServing(sipPort, done); err != nil {
		t.Fatalf("trunk plane never served: %v", err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/status", adminPort)
	deadline := time.Now().Add(3 * time.Second)
	for {
		res, err := http.Get(url)
		if err == nil {
			res.Body.Close()
			return // the admin API is up
		}
		if time.Now().After(deadline) {
			t.Fatalf("admin API configured at startup never came up after a mid-startup reload: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
