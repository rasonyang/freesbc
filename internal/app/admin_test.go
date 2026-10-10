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
	deps := adminDeps(edgeSrv, "test", cfg, store)

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

// The drain closures reach the edge's runtime state, and the Proxy snapshot
// carries the gauge for /metrics.
func TestAdminDepsDrain(t *testing.T) {
	cfg, err := config.Parse([]byte(edgeOnlyYAML))
	if err != nil {
		t.Fatal(err)
	}
	edgeSrv, err := edge.New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)),
		edge.WithPrivateAddr(netip.MustParseAddrPort("127.0.0.1:10054")))
	if err != nil {
		t.Fatal(err)
	}
	deps := adminDeps(edgeSrv, "test", cfg, config.NewStore(cfg))
	if on, _ := deps.DrainState(); on || deps.Proxy().Draining {
		t.Fatal("a fresh edge must start not draining")
	}
	if !deps.SetDraining(true) {
		t.Error("entering drain reported no change")
	}
	if on, since := deps.DrainState(); !on || since.IsZero() {
		t.Errorf("DrainState = %v, %v after entering", on, since)
	}
	if !deps.Proxy().Draining {
		t.Error("Proxy().Draining is false while draining")
	}
	if !deps.SetDraining(false) {
		t.Error("leaving drain reported no change")
	}
	if on, _ := deps.DrainState(); on {
		t.Error("still draining after leaving")
	}
}

// The live-state closures reach the edge and return non-nil, empty results
// on a fresh edge.
func TestAdminDepsLiveState(t *testing.T) {
	cfg, err := config.Parse([]byte(edgeOnlyYAML))
	if err != nil {
		t.Fatal(err)
	}
	edgeSrv, err := edge.New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)),
		edge.WithPrivateAddr(netip.MustParseAddrPort("127.0.0.1:10055")))
	if err != nil {
		t.Fatal(err)
	}
	deps := adminDeps(edgeSrv, "test", cfg, config.NewStore(cfg))

	if page, total := deps.Registrations("", 10, 0); page == nil || len(page) != 0 || total != 0 {
		t.Errorf("Registrations = %v, %d; want empty non-nil, 0", page, total)
	}
	if got := deps.CarrierRegistrations(); got == nil || len(got) != 0 {
		t.Errorf("CarrierRegistrations = %v, want empty non-nil", got)
	}
	if page, total, rejected := deps.Bans(10, 0); page == nil || len(page) != 0 || total != 0 || rejected != 0 {
		t.Errorf("Bans = %v, %d, %d; want empty non-nil, 0, 0", page, total, rejected)
	}
	nodes := deps.SwitchNodes()
	if len(nodes) != 1 || nodes[0].Address != "127.0.0.1:10052" || nodes[0].State != "healthy" || !nodes[0].LastFailure.IsZero() {
		t.Errorf("SwitchNodes = %+v, want one healthy node 127.0.0.1:10052", nodes)
	}
	if got := deps.Carriers(); got == nil || len(got) != 0 {
		t.Errorf("Carriers = %v, want empty non-nil", got)
	}
}
