package app

import (
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/edge"
	"github.com/freesbc/freesbc/internal/trunk"
)

// edgeOnlyYAML is an edge-only config. edge.New binds nothing, so its
// ports are never opened; they sit in this package's band anyway.
const edgeOnlyYAML = `
network:
  public:  { bind_ip: 127.0.0.1, advertised_ip: 127.0.0.1 }
  private: { bind_ip: 127.0.0.1, advertised_ip: 127.0.0.1 }
sip:
  public:
    udp: { enabled: true, bind: "127.0.0.1:10050" }
  private:
    bind: "127.0.0.1:10051"
  upstream:
    address: 127.0.0.1:10052
rtp:
  public:  { port_min: 10010, port_max: 10019 }
  private: { port_min: 10020, port_max: 10029 }
`

// audit: P2-APP-005
// In an edge-only process the admin view reports the edge plane: its media
// pools (not the idle trunk pool, which would report the default range),
// and the listeners it bound, which a reload does not move.
func TestAdminDepsReportRunningPlanes(t *testing.T) {
	cfg, err := config.Parse([]byte(edgeOnlyYAML))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewStore(cfg)
	edgeSrv, err := edge.New(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	deps := adminDeps(store, trunk.NewMediaPool(store), nil, edgeSrv, "test")

	if inUse, total := deps.Ports(); inUse != 0 || total != 10 {
		t.Errorf("Ports = %d/%d, want 0/10 (the edge pools' 5+5 pairs)", inUse, total)
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
	if got := deps.Listeners(); !slices.Equal(got, want) {
		t.Errorf("after a reload moving the public listener, Listeners = %q, want the bound %q", got, want)
	}
}
