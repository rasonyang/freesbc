package shield

import (
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestNFT builds an nftBackend with a recording exec func, bypassing
// availability detection (so tests run on any OS).
func newTestNFT(t *testing.T) (*nftBackend, *[]string) {
	t.Helper()
	var cmds []string
	n := &nftBackend{log: discard(), run: func(args ...string) error {
		cmds = append(cmds, strings.Join(args, " "))
		return nil
	}}
	return n, &cmds
}

func TestNFTBanArgv(t *testing.T) {
	n, cmds := newTestNFT(t)
	n.ban(netip.MustParseAddr("203.0.113.7"), time.Hour)
	n.ban(netip.MustParseAddr("2001:db8::1"), 30*time.Minute)
	joined := strings.Join(*cmds, "\n")
	if !strings.Contains(joined, "add element inet freesbc banned4 { 203.0.113.7 timeout 3600s }") {
		t.Errorf("v4 ban argv wrong:\n%s", joined)
	}
	if !strings.Contains(joined, "add element inet freesbc banned6 { 2001:db8::1 timeout 1800s }") {
		t.Errorf("v6 ban argv wrong:\n%s", joined)
	}
}

func TestNFTCloseTearsDown(t *testing.T) {
	n, cmds := newTestNFT(t)
	*cmds = nil
	if err := n.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(*cmds) != 1 || !strings.Contains((*cmds)[0], "delete table inet freesbc") {
		t.Errorf("close should delete the table, got %v", *cmds)
	}
}

func TestNFTModeOffReturnsNil(t *testing.T) {
	if n := newNFTBackend("off", discard()); n != nil {
		t.Fatal("mode off → nil backend")
	}
}
