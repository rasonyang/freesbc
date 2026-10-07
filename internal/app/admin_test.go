package app

import (
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/edge"
)

// edgeOnlyYAML is an edge-only config. edge.New binds nothing, so its
// ports are never opened; they sit in this package's band anyway. The
// private socket is moved to loopback by edge.WithPrivateAddr.
const edgeOnlyYAML = `
public: { ip: 127.0.0.1 }
private: { ip: 192.0.2.250 }
rtp: 10010-10019
edge:
  switch: [127.0.0.1:10052]
  listen: { udp: 10050 }
`

// audit: P2-APP-005
// In an edge-only process the admin view reports the edge plane: its media
// pools and the listeners it bound, which a reload does not move.
func TestAdminDepsReportRunningPlanes(t *testing.T) {
	cfg, err := config.Parse([]byte(edgeOnlyYAML))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewStore(cfg)
	edgeSrv, err := edge.New(store, slog.New(slog.NewTextHandler(io.Discard, nil)),
		edge.WithPrivateAddr(netip.MustParseAddrPort("127.0.0.1:10051")))
	if err != nil {
		t.Fatal(err)
	}
	deps := adminDeps(edgeSrv, "test", cfg)

	if inUse, total := deps.Ports(); inUse != 0 || total != 10 {
		t.Errorf("Ports = %d/%d, want 0/10 (the public and private pools' 5 pairs each)", inUse, total)
	}
	if n, calls := deps.ActiveCalls(), deps.Calls(); n != 0 || len(calls) != 0 {
		t.Errorf("ActiveCalls = %d, Calls = %v; want 0 and none", n, calls)
	}

	want := []string{"udp://127.0.0.1:10050", "udp://127.0.0.1:10051 (private)"}
	if got := deps.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners = %q, want %q", got, want)
	}
	moved, err := config.Parse([]byte(strings.Replace(edgeOnlyYAML, "10050", "10053", 1)))
	if err != nil {
		t.Fatal(err)
	}
	store.Replace(moved)
	if deps.Running() != cfg {
		t.Error("Running must stay the startup snapshot across a reload")
	}
	if got := deps.Listeners(); !slices.Equal(got, want) {
		t.Errorf("after a reload moving the public listener, Listeners = %q, want the bound %q", got, want)
	}
}
