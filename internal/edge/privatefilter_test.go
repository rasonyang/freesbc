package edge

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"syscall"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
)

// localInterface finds the interface that owns an address, which is what
// checkLocalAddr and the private socket's ingress filter both rest on.
func TestLocalInterface(t *testing.T) {
	name, ok, err := localInterface(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("localInterface(127.0.0.1): %v", err)
	}
	if !ok || name == "" {
		t.Fatalf("localInterface(127.0.0.1) = %q, %v; want a named interface", name, ok)
	}
	if _, ok, err := localInterface(netip.MustParseAddr("192.0.2.250")); err != nil || ok {
		t.Fatalf("localInterface(192.0.2.250) = _, %v, %v; want not found", ok, err)
	}
}

// privateSocketFilter is Linux-only; elsewhere it must stay a no-op so the
// private socket keeps working and Run logs the warning.
func TestPrivateSocketFilterPlatform(t *testing.T) {
	control, err := privateSocketFilter("lo")
	if runtime.GOOS == "linux" {
		if err != nil || control == nil {
			t.Fatalf("privateSocketFilter on Linux: non-nil=%v, err=%v; want a control", control != nil, err)
		}
		return
	}
	if err != nil || control != nil {
		t.Fatalf("privateSocketFilter off Linux: non-nil=%v, err=%v; want nil, nil", control != nil, err)
	}
}

// TestPrivateListenerWiresTheFilter proves openListener asks for the private
// socket's filter with the interface that owns private.ip, and only for
// udp-private: the control it returns runs when the socket is created.
func TestPrivateListenerWiresTheFilter(t *testing.T) {
	old := privateSocketFilter
	defer func() { privateSocketFilter = old }()
	var called []string
	privateSocketFilter = func(ifname string) (func(network, address string, c syscall.RawConn) error, error) {
		return func(_, _ string, _ syscall.RawConn) error {
			called = append(called, ifname)
			return nil
		}, nil
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
public: {ip: 127.0.0.1}
private: {ip: 192.0.2.250}
edge:
  switch: [127.0.0.1:5060]
  listen: {udp: %d}
`, nextPort(t))))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithPrivateAddr(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", nextPort(t)))))
	if err != nil {
		t.Fatal(err)
	}
	ifname, ok, err := localInterface(srv.privAddr.Addr())
	if err != nil || !ok {
		t.Fatalf("localInterface(%s) = %q, %v, %v", srv.privAddr.Addr(), ifname, ok, err)
	}

	priv, err := srv.openListener("udp-private", srv.privAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Close()
	if len(called) != 1 || called[0] != ifname {
		t.Fatalf("private listener control calls = %v, want [%s]", called, ifname)
	}

	pub, err := srv.openListener("udp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(nextPort(t))).String())
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	if len(called) != 1 {
		t.Fatalf("public listener invoked the private filter control: %v", called)
	}
}
