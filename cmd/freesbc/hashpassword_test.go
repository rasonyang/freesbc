package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/freesbc/freesbc/internal/admin"
	"github.com/freesbc/freesbc/internal/config"
)

func hashFrom(t *testing.T, stdin string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if code := hashPassword(strings.NewReader(stdin), &out, &errb, nil); code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty in stdin mode, got %q", errb.String())
	}
	s := out.String()
	if !strings.HasSuffix(s, "\n") || strings.Count(s, "\n") != 1 {
		t.Fatalf("stdout must be one hash and a newline, got %q", s)
	}
	return strings.TrimSuffix(s, "\n")
}

// The hash from stdin mode has the required cost, passes config validation
// and logs in to the admin API.
func TestHashPasswordStdinWorksForAdmin(t *testing.T) {
	hash := hashFrom(t, "s3cret pw\n")
	if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost != config.MinBcryptCost {
		t.Fatalf("cost = %d, %v; want %d", cost, err, config.MinBcryptCost)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := l.Addr().String()
	_ = l.Close()
	yaml := fmt.Sprintf(`
public: { ip: 127.0.0.1 }
private: { ip: 192.0.2.250 }
rtp: 10010-10029
edge:
  switch: [127.0.0.1:5062]
  listen: { udp: 5060 }
admin:
  listen: %s
  password_hash: %q
`, listen, hash)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config rejects the generated hash: %v", err)
	}

	deps := admin.Deps{
		Calls:       func() []admin.Call { return nil },
		Ports:       func() (int, int) { return 0, 0 },
		Shield:      func() admin.ShieldStats { return admin.ShieldStats{} },
		ActiveCalls: func() int { return 0 },
	}
	srv := admin.New(cfg.Admin, nil, config.NewStore(cfg), deps, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	status := func(pw string) int {
		req, _ := http.NewRequest(http.MethodGet, "http://"+listen+"/api/calls", nil)
		req.SetBasicAuth(config.AdminUser, pw)
		for deadline := time.Now().Add(5 * time.Second); ; {
			res, err := http.DefaultClient.Do(req)
			if err == nil {
				res.Body.Close()
				return res.StatusCode
			}
			if time.Now().After(deadline) {
				t.Fatalf("admin API never came up: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	if got := status("s3cret pw"); got != http.StatusOK {
		t.Errorf("right password: status %d, want 200", got)
	}
	if got := status("wrong"); got != http.StatusUnauthorized {
		t.Errorf("wrong password: status %d, want 401", got)
	}
}

func TestHashPasswordLineEndings(t *testing.T) {
	for in, want := range map[string]string{
		"pw":       "pw",
		"pw\n":     "pw",
		"pw\r\n":   "pw",
		"pw \n":    "pw ",
		" pw\n":    " pw",
		"pw\nmore": "pw",
		"pw\r\r\n": "pw\r",
	} {
		hash := hashFrom(t, in)
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(want)) != nil {
			t.Errorf("stdin %q: hash does not match %q", in, want)
		}
	}
}

func TestHashPasswordErrors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"only EOL":  "\n",
		"only CRLF": "\r\n",
		"too long":  strings.Repeat("a", 73) + "\n",
	} {
		var out, errb bytes.Buffer
		if code := hashPassword(strings.NewReader(in), &out, &errb, nil); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
		if out.Len() != 0 || errb.Len() == 0 {
			t.Errorf("%s: stdout=%q stderr=%q; want an error on stderr only", name, out.String(), errb.String())
		}
	}
}

func TestHashPasswordArgumentIsUsageError(t *testing.T) {
	for _, args := range [][]string{
		{"hash-password", "foo"},
		{"hash-password", "-c", "x.yaml"},
		{"hash-password", "--password=foo"},
		{"hash-password", "-h", "foo"},
	} {
		if got := run(args); got != 2 {
			t.Errorf("run(%q) = %d, want 2", args, got)
		}
	}
	if got := run([]string{"hash-password", "--help"}); got != 0 {
		t.Errorf("hash-password --help = %d, want 0", got)
	}
}

// The terminal path, through the readPass seam.
func TestHashPasswordTerminal(t *testing.T) {
	seq := func(entries ...string) func() ([]byte, error) {
		return func() ([]byte, error) {
			if len(entries) == 0 {
				return nil, errors.New("no more input")
			}
			e := entries[0]
			entries = entries[1:]
			return []byte(e), nil
		}
	}
	var out, errb bytes.Buffer
	if code := hashPassword(strings.NewReader("ignored"), &out, &errb, seq("pw", "pw")); code != 0 {
		t.Fatalf("matching entries: exit %d, stderr=%q", code, errb.String())
	}
	if bcrypt.CompareHashAndPassword(bytes.TrimSpace(out.Bytes()), []byte("pw")) != nil {
		t.Errorf("hash %q does not match pw", out.String())
	}
	if !strings.Contains(errb.String(), "Password:") || strings.Contains(out.String(), "Password:") {
		t.Errorf("prompts must go to stderr only: stdout=%q stderr=%q", out.String(), errb.String())
	}

	out.Reset()
	errb.Reset()
	if code := hashPassword(nil, &out, &errb, seq("pw", "other")); code != 1 {
		t.Errorf("mismatch: exit %d, want 1", code)
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "do not match") {
		t.Errorf("mismatch: stdout=%q stderr=%q", out.String(), errb.String())
	}

	out.Reset()
	errb.Reset()
	if code := hashPassword(nil, &out, &errb, seq("", "")); code != 1 || out.Len() != 0 {
		t.Errorf("empty on terminal: exit %d stdout=%q, want 1 and nothing", code, out.String())
	}
}
