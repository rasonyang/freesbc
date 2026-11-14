package app

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/freesbc/freesbc/internal/edge"
)

const (
	rmemLine = "net.core.rmem_max 212992 < 8388608 requested by every UDP SIP socket: datagrams may drop silently under bursts; add /etc/sysctl.d/90-freesbc.conf (docs/edge.md#udp-socket-buffers)\n"
	wmemLine = "net.core.wmem_max 212992 < 1048576 requested by every UDP SIP socket: sends may stall under bursts; add /etc/sysctl.d/90-freesbc.conf (docs/edge.md#udp-socket-buffers)\n"
)

func TestUDPBufferNote(t *testing.T) {
	files := func(r, w string) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			switch p {
			case "/proc/sys/net/core/rmem_max":
				return []byte(r), nil
			case "/proc/sys/net/core/wmem_max":
				return []byte(w), nil
			}
			return nil, errors.New("unexpected path " + p)
		}
	}
	fail := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	for _, tc := range []struct {
		name string
		goos string
		read func(string) ([]byte, error)
		want string
	}{
		{"both below", "linux", files("212992\n", "212992\n"), rmemLine + wmemLine},
		{"rmem only", "linux", files("212992\n", "1048576\n"), rmemLine},
		{"wmem only", "linux", files("8388608\n", "212992\n"), wmemLine},
		{"equal", "linux", files("8388608\n", "1048576\n"), ""},
		{"above", "linux", files("16777216\n", "4194304"), ""},
		{"unreadable", "linux", fail, ""},
		{"garbage", "linux", files("lots\n", ""), ""},
		{"non-linux", "darwin", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := udpBufferNote(tc.goos, tc.read); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestInstallScriptBufferNumbers keeps install.sh's sysctl thresholds equal
// to what the edge requests.
func TestInstallScriptBufferNumbers(t *testing.T) {
	b, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	rcv, snd := edge.UDPSIPBuffers()
	for name, want := range map[string]int{"RMEM_WANT": rcv, "WMEM_WANT": snd} {
		m := regexp.MustCompile(`(?m)^\s*` + name + `=(\d+)$`).FindSubmatch(b)
		if m == nil {
			t.Fatalf("install.sh has no %s=<number>", name)
		}
		if got, _ := strconv.Atoi(string(m[1])); got != want {
			t.Errorf("install.sh %s=%d, edge requests %d", name, got, want)
		}
	}
}
