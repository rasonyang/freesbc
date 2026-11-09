package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The single-IP layout (issue #320): one address faces both the switch and,
// through a 1:1 NAT, the internet. init writes it and prints the
// shared-socket note.
func TestInitSingleIPLayout(t *testing.T) {
	o, _ := fakeInit(t, "10.0.0.2", "10.0.0.2", "203.0.113.7")
	o.Switch = "10.0.0.5:5080"
	var out strings.Builder
	o.Out = &out
	if err := Init(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	c := parseFile(t, o.Path)
	if !c.SharedSocket() || c.Public.IP != "203.0.113.7" || c.Public.Bind != "10.0.0.2" || c.Private.IP != "10.0.0.2" {
		t.Errorf("got %+v %+v", c.Public, c.Private)
	}
	for _, w := range []string{"single-IP layout", "identified by its source IP", "REQUIRED forwards: udp/5060"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("output lacks %q:\n%s", w, out.String())
		}
	}
	if strings.Contains(out.String(), "provider") {
		t.Errorf("output asks about provider filtering:\n%s", out.String())
	}

	// The layout's own rules still apply: udp 5060 only.
	o, _ = fakeInit(t, "10.0.0.2", "10.0.0.2", "203.0.113.7")
	o.Switch, o.UDPPort = "10.0.0.5:5080", 5070
	if err := Init(context.Background(), o); err == nil || !strings.Contains(err.Error(), "must be 5060") {
		t.Fatalf("err = %v, want the udp 5060 rule", err)
	}
	if _, serr := os.Stat(o.Path); !errors.Is(serr, os.ErrNotExist) {
		t.Error("file written despite error")
	}
}

// check adds the shared-socket note only when private.ip equals public.bind.
func TestCheckSharedSocketNote(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	src := "public: { ip: 203.0.113.7, bind: 10.77.0.2 }\nprivate: { ip: 10.77.0.2 }\nedge:\n  switch: [10.77.0.3:5080]\n  listen: { udp: 5060 }\n"
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	note, err := Check(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"one UDP socket (10.77.0.2:5060) serves both sides", "identified by its source IP (10.77.0.3)", "REQUIRED forwards: udp/5060 and the rtp range 20000-29999"} {
		if !strings.Contains(note, w) {
			t.Errorf("note lacks %q:\n%s", w, note)
		}
	}
	// A NAT config with separate addresses gets no such note.
	sep := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(sep, []byte(strings.Replace(src, "bind: 10.77.0.2", "bind: 172.20.0.4", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if note, err := Check(sep); err != nil || strings.Contains(note, "single-IP") {
		t.Errorf("separate-address note = %q, %v", note, err)
	}
}
