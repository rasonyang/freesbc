package app

import (
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/admin"
	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/edge"
)

type healthClock struct{ t time.Time }

func (c *healthClock) now() time.Time { return c.t }

func newTestHealth() (*healthSource, *healthClock) {
	clk := &healthClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	return &healthSource{now: clk.now}, clk
}

// find returns the condition with the given id.
func find(t *testing.T, conds []admin.HealthCondition, id string) (admin.HealthCondition, bool) {
	t.Helper()
	for _, c := range conds {
		if c.ID == id {
			return c, true
		}
	}
	return admin.HealthCondition{}, false
}

func ids(conds []admin.HealthCondition) []string {
	out := []string{}
	for _, c := range conds {
		out = append(out, c.ID)
	}
	slices.Sort(out)
	return out
}

func TestHealthSwitchCooldown(t *testing.T) {
	h, _ := newTestHealth()
	nodes := func(a, b bool) healthInputs {
		return healthInputs{Switch: []edge.SwitchNode{{Addr: "10.0.0.1:5060", Cooling: a}, {Addr: "10.0.0.2:5060", Cooling: b}}}
	}
	if got := h.derive(nodes(false, false)); len(got) != 0 {
		t.Fatalf("healthy = %v", ids(got))
	}
	got := h.derive(nodes(true, false))
	c, ok := find(t, got, "switch_cooldown:10.0.0.1:5060")
	if !ok || len(got) != 1 || c.Severity != admin.HealthDegraded {
		t.Fatalf("one node cooling = %+v, want one degraded condition", got)
	}
	got = h.derive(nodes(true, true))
	if len(got) != 2 {
		t.Fatalf("all cooling = %v", ids(got))
	}
	for _, c := range got {
		if c.Severity != admin.HealthCritical {
			t.Errorf("%s = %s, want critical when every node is cooling", c.ID, c.Severity)
		}
	}
	if got := h.derive(nodes(false, true)); len(got) != 1 || got[0].Severity != admin.HealthDegraded {
		t.Errorf("after the first recovered = %+v", got)
	}
	// A single-node pool that cools is every node.
	one := healthInputs{Switch: []edge.SwitchNode{{Addr: "10.0.0.1:5060", Cooling: true}}}
	if got := h.derive(one); len(got) != 1 || got[0].Severity != admin.HealthCritical {
		t.Errorf("single node cooling = %+v, want critical", got)
	}
	one.Switch[0].Cooling = false
	if got := h.derive(one); len(got) != 0 {
		t.Errorf("single node recovered = %v", ids(got))
	}
}

func TestHealthCarrierDNS(t *testing.T) {
	h, _ := newTestHealth()
	with := func(d edge.CarrierDNS) healthInputs { return healthInputs{CarrierDNS: []edge.CarrierDNS{d}} }
	if got := h.derive(with(edge.CarrierDNS{Name: "acme", Addrs: 2})); len(got) != 0 {
		t.Fatalf("healthy = %v", ids(got))
	}
	got := h.derive(with(edge.CarrierDNS{Name: "acme", Failing: true, Addrs: 2}))
	if c, ok := find(t, got, "carrier_dns:acme"); !ok || c.Severity != admin.HealthDegraded {
		t.Fatalf("stale set = %+v, want degraded", got)
	}
	got = h.derive(with(edge.CarrierDNS{Name: "acme", Failing: true}))
	if c, ok := find(t, got, "carrier_dns:acme"); !ok || c.Severity != admin.HealthCritical {
		t.Fatalf("no address = %+v, want critical", got)
	}
	if got := h.derive(with(edge.CarrierDNS{Name: "acme", Addrs: 1})); len(got) != 0 {
		t.Errorf("recovered = %v", ids(got))
	}
}

func TestHealthRTPPorts(t *testing.T) {
	h, _ := newTestHealth()
	for _, tc := range []struct {
		inUse, total int
		want         admin.HealthSeverity // "" means no condition
	}{
		{0, 0, ""},
		{89, 100, ""},
		{90, 100, admin.HealthDegraded},
		{99, 100, admin.HealthDegraded},
		{100, 100, admin.HealthCritical},
		{9, 10, admin.HealthDegraded},
		{8, 10, ""},
	} {
		got := h.derive(healthInputs{PortsInUse: tc.inUse, PortsTotal: tc.total})
		c, ok := find(t, got, "rtp_ports")
		if tc.want == "" && ok || tc.want != "" && (!ok || c.Severity != tc.want) {
			t.Errorf("%d/%d = %+v, want %q", tc.inUse, tc.total, got, tc.want)
		}
	}
}

// shield_ban_cap is raised when the counter rises and cleared after it
// has stood still for banCapQuiet; a further rise restarts the wait.
func TestHealthShieldBanCap(t *testing.T) {
	h, clk := newTestHealth()
	active := func(n int64) bool {
		_, ok := find(t, h.derive(healthInputs{BanRejected: n}), "shield_ban_cap")
		return ok
	}
	if active(0) {
		t.Fatal("raised with a zero counter")
	}
	clk.t = clk.t.Add(5 * time.Second)
	if !active(3) {
		t.Fatal("not raised when the counter rose")
	}
	clk.t = clk.t.Add(banCapQuiet - time.Second)
	if !active(3) {
		t.Fatal("cleared before the counter was quiet for banCapQuiet")
	}
	clk.t = clk.t.Add(2 * time.Second) // 61 s without a rise
	if active(3) {
		t.Fatal("not cleared after banCapQuiet without a rise")
	}
	clk.t = clk.t.Add(time.Hour)
	if active(3) {
		t.Fatal("raised again with no new rejection")
	}
	if !active(4) {
		t.Fatal("not raised by a new rejection")
	}
	clk.t = clk.t.Add(banCapQuiet - time.Second)
	if !active(5) { // rises again: the wait restarts
		t.Fatal("not still raised")
	}
	clk.t = clk.t.Add(banCapQuiet - time.Second)
	if !active(5) {
		t.Fatal("cleared early although the counter rose within banCapQuiet")
	}
	clk.t = clk.t.Add(2 * time.Second)
	if active(5) {
		t.Fatal("not cleared")
	}
}

func TestHealthAdminPlainRemote(t *testing.T) {
	tls := &config.TLSConfig{Cert: "c", Key: "k"}
	for _, tc := range []struct {
		name string
		cfg  *config.AdminConfig
		tls  *config.TLSConfig
		want bool
	}{
		{"no admin", nil, nil, false},
		{"loopback plain", &config.AdminConfig{Listen: "127.0.0.1:8080"}, nil, false},
		{"v6 loopback plain", &config.AdminConfig{Listen: "[::1]:8080"}, nil, false},
		{"remote plain", &config.AdminConfig{Listen: "10.0.0.5:8080"}, nil, true},
		{"remote allowed without tls", &config.AdminConfig{Listen: "10.0.0.5:8080", AllowRemote: true}, nil, true},
		{"remote with tls", &config.AdminConfig{Listen: "10.0.0.5:8080", AllowRemote: true}, tls, false},
	} {
		if got := adminPlainRemote(tc.cfg, tc.tls); got != tc.want {
			t.Errorf("%s: adminPlainRemote = %v, want %v", tc.name, got, tc.want)
		}
		h, _ := newTestHealth()
		c, ok := find(t, h.derive(healthInputs{AdminPlainRemote: tc.want}), "admin_plain_remote")
		if ok != tc.want || ok && c.Severity != admin.HealthCritical {
			t.Errorf("%s: condition = %+v, %v", tc.name, c, ok)
		}
	}
}

// adminDeps wires Health to a real edge: a fresh edge-only plane has no
// active condition.
func TestAdminDepsHealthWired(t *testing.T) {
	cfg, err := config.Parse([]byte(edgeOnlyYAML))
	if err != nil {
		t.Fatal(err)
	}
	edgeSrv, err := edge.New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)),
		edge.WithPrivateAddr(netip.MustParseAddrPort("127.0.0.1:10054")))
	if err != nil {
		t.Fatal(err)
	}
	deps := adminDeps(edgeSrv, "test", cfg)
	if deps.Health == nil {
		t.Fatal("Deps.Health is nil")
	}
	if got := deps.Health(); len(got) != 0 {
		t.Errorf("fresh edge reports conditions %v", ids(got))
	}
}
