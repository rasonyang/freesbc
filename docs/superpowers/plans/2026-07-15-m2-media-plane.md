# FreeSBC M2 — Media Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `media` package that allocates RTP/RTCP port pairs from the configured range and relays UDP packets between two call legs with hardened first-packet latching and silence-timeout teardown — plus the M1 carry-over config fixes.

**Architecture:** A `Pool` reads the port range from the config store on every allocation (hot-reloaded ranges apply to new calls). Each call gets a `Session`: two bound `PortPair`s (side A / side B; RTP on an even port, RTCP on RTP+1), four goroutine read-loops forwarding packets to the opposite side's latched remote, and a watchdog that tears the session down after RTP silence. A `latch` fixes each stream's remote on the first accepted packet and never moves (RTP-hijack hardening, spec §3 decision 5); strict mode additionally requires the first packet's source IP to match the SDP-signaled address. The media plane knows nothing about SIP — M3's signaling plane will call `Allocate`, write `RTPPort(side)` into rewritten SDP, and call `SetExpectedRemote` from the peer's SDP `c=` line.

**Tech Stack:** Go stdlib only for the media plane (`net`, `net/netip`, `sync`, `sync/atomic`, `time`). Config changes reuse goccy/go-yaml. **No new dependencies in M2.**

**Roadmap context:** Plan 2 of the FreeSBC MVP (spec: `freesbc-allinone-design.md`; M1 backlog: `docs/superpowers/plans/2026-07-15-m1-config-foundation.md` § Carry-over Backlog). Deferred from M2 intentionally: STUN resolution of `public_ip: auto` (M3 — SDP rewriting is its only consumer), `SO_REUSEPORT`/batch-syscall performance work (needs an end-to-end call to benchmark, M3+), SRTP (M5), Prometheus counters (M7).

## Global Constraints

- Module path `github.com/freesbc/freesbc`, Go ≥ 1.22. Dependencies: goccy/go-yaml + fsnotify only — the `media` package itself imports **stdlib only** (it may import the project's own `config` package).
- All code, comments, and log messages in English. Tests use stdlib `testing` only.
- Every task: `gofmt -l .` must print nothing before committing; final task runs `go vet ./... && go test ./... -race`.
- Config lifecycle contract (from M1, `config/schema.go` doc): `config.Parse` is the only public entry; published `*Config` snapshots are immutable; modules read via `(*config.Store).Current()`.
- Spec §7 rows that bind this plan: media port exhaustion → caller-visible error (sig maps it to 503 in M3); per-call goroutine panic → recover, kill that call only, release its resources, process never dies; half-dead call → RTP silence timeout (default 5 minutes) tears the session down.
- Spec §3 decision 5 (latching): latch only before media flows, never re-latch; strict mode (default) requires the first packet's source IP to match the SDP-signaled IP; `strict`/`loose` configurable per peer.
- Interface deviation from the spec's §4 sketch (`media.Allocate(ctx) (Session, error)`): the as-built API is `(*Pool).Allocate(SessionConfig) (*Session, error)` — no ctx (binding doesn't block), explicit per-session latch/timeout config. Session teardown is observable via `Done()`.
- Integration tests bind fixed localhost UDP ports in the 40000–41299 range. If a CI machine has collisions there, shift the ranges — the values are arbitrary.

---

### Task 1: Config carry-over — quoted custom scalars + single error prefix

The M1 final review found that quoting any custom-scalar value breaks parsing (`port_range: "16384-32768"`, `window: "60s"`, `sip: ["udp://..."]` all fail) because `UnmarshalYAML([]byte)` receives the raw YAML node *including quote characters*. Also, `check` prints a doubled prefix (`config invalid:` from main.go + `invalid config:` from Parse).

**Files:**
- Modify: `config/types.go` (all three `UnmarshalYAML` methods + new helper)
- Modify: `main.go` (the `check` error print)
- Test: `config/types_test.go`, `config/loader_test.go`

**Interfaces:**
- Consumes: existing `Duration`, `PortRange`, `SIPListen` types and their `UnmarshalYAML([]byte) error` methods (config/types.go); `Parse([]byte) (*Config, error)` (config/loader.go).
- Produces: no signature changes — behavior fix only. Package-private helper `yamlScalarString(b []byte) (string, error)` in config/types.go.

- [ ] **Step 1: Write the failing tests**

Add to `config/types_test.go` (inside the existing test functions, after the current success cases):

```go
// In TestDurationUnmarshalYAML, after the existing 90s case:
	if err := d.UnmarshalYAML([]byte(`"90s"`)); err != nil {
		t.Fatalf("quoted duration must parse: %v", err)
	}
	if d.Std() != 90*time.Second {
		t.Errorf("quoted: got %v, want 90s", d.Std())
	}

// In TestPortRangeUnmarshalYAML, after the existing success case:
	if err := p.UnmarshalYAML([]byte(`"16384-32768"`)); err != nil {
		t.Fatalf("quoted port range must parse: %v", err)
	}
	if p.Min != 16384 || p.Max != 32768 {
		t.Errorf("quoted: got %d-%d", p.Min, p.Max)
	}

// In TestSIPListenUnmarshalYAML, after the existing success cases:
	if err := s.UnmarshalYAML([]byte(`"udp://0.0.0.0:5060"`)); err != nil {
		t.Fatalf("quoted listener must parse: %v", err)
	}
	if s.Transport != "udp" || s.Port != 5060 {
		t.Errorf("quoted: got %+v", s)
	}
```

Add to `config/loader_test.go`:

```go
func TestParseQuotedScalars(t *testing.T) {
	src := `
listen:
  sip: ["udp://0.0.0.0:5060"]
  media:
    port_range: "16384-32768"
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: pbx
    to: [pbx]
shield:
  auto_ban: { failures: 5, window: "60s", duration: 1h }
`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("quoted scalars must parse: %v", err)
	}
	if c.Listen.SIP[0].Port != 5060 {
		t.Errorf("listener: %+v", c.Listen.SIP[0])
	}
	if c.Listen.Media.PortRange.Min != 16384 {
		t.Errorf("port range: %+v", c.Listen.Media.PortRange)
	}
	if c.Shield.AutoBan.Window.Std() != 60*time.Second {
		t.Errorf("window: %v", c.Shield.AutoBan.Window.Std())
	}
}
```

(`config/loader_test.go` already imports `testing` and `strings`; add `time` to its imports if not present.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/ -run 'TestDurationUnmarshalYAML|TestPortRangeUnmarshalYAML|TestSIPListenUnmarshalYAML|TestParseQuotedScalars' -v`
Expected: FAIL — quoted inputs produce errors like `invalid duration "\"90s\""`.

- [ ] **Step 3: Implement the fix**

In `config/types.go`, add the helper (and `github.com/goccy/go-yaml` to the imports):

```go
// yamlScalarString decodes one YAML scalar node to its string value,
// handling quoting and escapes; UnmarshalYAML receives raw node bytes
// which include any quote characters the user wrote.
func yamlScalarString(b []byte) (string, error) {
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return "", err
	}
	return strings.TrimSpace(s), nil
}
```

Change the head of each of the three `UnmarshalYAML` methods to decode via the helper. `Duration`:

```go
func (d *Duration) UnmarshalYAML(b []byte) error {
	s, err := yamlScalarString(b)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", string(b), err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}
```

`PortRange` — replace `s := strings.TrimSpace(string(b))` with:

```go
	s, err := yamlScalarString(b)
	if err != nil {
		return fmt.Errorf("invalid port range %q: %w", string(b), err)
	}
```

`SIPListen` — replace `raw := strings.TrimSpace(string(b))` with:

```go
	raw, err := yamlScalarString(b)
	if err != nil {
		return fmt.Errorf("invalid listener %q: %w", string(b), err)
	}
```

In `main.go`, fix the doubled prefix — `Parse`/`Load` errors already carry their own prefix (`invalid config:` / `parse config:` / `read config:`):

```go
	case "check":
		if _, err := config.Load(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
```

- [ ] **Step 4: Run the config suite**

Run: `go test ./config/ -v && go build -o freesbc . && printf 'bogus: config' > /tmp/bad.yaml; ./freesbc check -c /tmp/bad.yaml; echo "exit=$?"`
Expected: tests PASS; check output shows a single `parse config:`-prefixed error (no `config invalid:` line), `exit=1`.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ main.go && git commit -m "fix(config): accept quoted custom scalars; drop doubled check error prefix"
```

---

### Task 2: Media config fields — `rtp_timeout` and `media_latch`

**Files:**
- Modify: `config/schema.go` (MediaConfig, Peer, withDefaults)
- Modify: `config/validate.go` (new checks)
- Modify: `sbc.example.yaml` (document the new fields)
- Test: `config/schema_test.go`, `config/validate_test.go`

**Interfaces:**
- Consumes: `MediaConfig`, `Peer`, `withDefaults`, `validate` from M1.
- Produces (Task 3+ and M3 rely on these): `MediaConfig.RTPTimeout Duration` (yaml `rtp_timeout`, default 5m, must be > 0), `Peer.MediaLatch string` (yaml `media_latch`, `"strict"` default | `"loose"`).

- [ ] **Step 1: Write the failing tests**

Add to `TestWithDefaults` in `config/schema_test.go`:

```go
	if c.Listen.Media.RTPTimeout.Std() != 5*time.Minute {
		t.Errorf("rtp_timeout default: %v", c.Listen.Media.RTPTimeout.Std())
	}
	if c.Peers["p"].MediaLatch != "strict" {
		t.Errorf("media_latch default: %q", c.Peers["p"].MediaLatch)
	}
```

Add to the `cases` table in `TestValidateErrors` in `config/validate_test.go`:

```go
		{"bad media_latch", func(c *Config) { c.Peers["pbx"].MediaLatch = "sticky" }, "media_latch"},
		{"negative rtp_timeout", func(c *Config) { c.Listen.Media.RTPTimeout = Duration(-time.Second) }, "rtp_timeout"},
```

(`config/validate_test.go` needs `time` in its imports if not already there.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/ -run 'TestWithDefaults|TestValidateErrors' -v`
Expected: FAIL — compile error (`RTPTimeout`, `MediaLatch` undefined).

- [ ] **Step 3: Implement**

`config/schema.go` — extend the structs:

```go
type MediaConfig struct {
	PortRange  PortRange `yaml:"port_range"`
	PublicIP   string    `yaml:"public_ip"`    // "auto" (STUN-detected) or a literal IP
	RTPTimeout Duration  `yaml:"rtp_timeout"`  // tear down a call after this much RTP silence
}
```

Add to `Peer` (after `AllowedIPs`):

```go
	// MediaLatch controls first-packet latching for this peer's media:
	// "strict" (default) requires the first RTP packet's source IP to match
	// the SDP-signaled address; "loose" accepts any source (hard NAT).
	MediaLatch string `yaml:"media_latch"`
```

Add to `withDefaults`:

```go
	if c.Listen.Media.RTPTimeout == 0 {
		c.Listen.Media.RTPTimeout = Duration(5 * time.Minute)
	}
```

and inside the existing peers loop:

```go
		if p.MediaLatch == "" {
			p.MediaLatch = "strict"
		}
```

`config/validate.go` — after the existing `public_ip` check:

```go
	if c.Listen.Media.RTPTimeout.Std() <= 0 {
		fail("listen.media.rtp_timeout: must be > 0, got %v", c.Listen.Media.RTPTimeout.Std())
	}
```

and inside the (sorted) peers loop, after the transport check:

```go
		switch p.MediaLatch {
		case "strict", "loose":
		default:
			fail("peers.%s: media_latch must be strict or loose, got %q", name, p.MediaLatch)
		}
```

`sbc.example.yaml` — extend the media section and carrier-a peer with commented documentation:

```yaml
  media:
    port_range: 16384-32768
    public_ip: auto                # auto = STUN probe, or set a literal IP
    # rtp_timeout: 5m              # tear down calls after this much RTP silence
```

and under `carrier-a`, after `allowed_ips`:

```yaml
    # media_latch: strict          # strict (default): first RTP packet must
    #                              # come from the SDP-signaled IP; use loose
    #                              # for peers behind hard NAT
```

- [ ] **Step 4: Run the config suite**

Run: `go test ./config/ -v && go build -o freesbc . && CARRIER_A_PASS=test ./freesbc check -c sbc.example.yaml`
Expected: PASS; `sbc.example.yaml: config OK`.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ sbc.example.yaml && git commit -m "feat(config): rtp_timeout and per-peer media_latch settings"
```

---

### Task 3: Port pool

**Files:**
- Create: `media/portpool.go`
- Test: `media/portpool_test.go`

**Interfaces:**
- Consumes: `config.Store`, `config.Config`, `config.ListenConfig`, `config.MediaConfig`, `config.PortRange`, `config.Duration`, `config.NewStore` (all from M1/Task 2).
- Produces (Tasks 4–5 and M3 rely on these):
  - `var ErrPortsExhausted error`
  - `type PortPair struct{ RTP, RTCP *net.UDPConn }` with `RTPPort() int` and `Close()`
  - `func NewPool(store *config.Store) *Pool`
  - `(p *Pool) allocatePair() (*PortPair, error)` and `(p *Pool) release(rtpPort int)` (package-private; `Allocate` in Task 4 is the public entry)

- [ ] **Step 1: Write the failing test**

Create `media/portpool_test.go`:

```go
package media

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/config"
)

// testStore builds a config store with the given media port range. Config
// fields are exported, so tests construct the snapshot directly.
func testStore(minPort, maxPort int) *config.Store {
	cfg := &config.Config{
		Listen: config.ListenConfig{
			Media: config.MediaConfig{
				PortRange:  config.PortRange{Min: uint16(minPort), Max: uint16(maxPort)},
				PublicIP:   "auto",
				RTPTimeout: config.Duration(5 * time.Minute),
			},
		},
	}
	return config.NewStore(cfg)
}

func TestPoolAllocateReleaseCycle(t *testing.T) {
	p := NewPool(testStore(40000, 40007)) // room for 4 pairs
	var pairs []*PortPair
	for i := 0; i < 4; i++ {
		pair, err := p.allocatePair()
		if err != nil {
			t.Fatalf("pair %d: %v", i, err)
		}
		if pair.RTPPort()%2 != 0 {
			t.Errorf("RTP port %d not even", pair.RTPPort())
		}
		pairs = append(pairs, pair)
	}
	if _, err := p.allocatePair(); !errors.Is(err, ErrPortsExhausted) {
		t.Fatalf("want ErrPortsExhausted, got %v", err)
	}
	pairs[0].Close()
	p.release(pairs[0].RTPPort())
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("re-allocate after release: %v", err)
	}
	pair.Close()
	for _, pp := range pairs[1:] {
		pp.Close()
	}
}

func TestPoolSkipsForeignBoundPort(t *testing.T) {
	// Occupy the first RTP port outside the pool; allocation must skip it.
	held, err := net.ListenUDP("udp", &net.UDPAddr{Port: 40100})
	if err != nil {
		t.Skipf("cannot bind fixture port: %v", err)
	}
	defer held.Close()
	p := NewPool(testStore(40100, 40103))
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer pair.Close()
	if got := pair.RTPPort(); got != 40102 {
		t.Errorf("got port %d, want 40102 (40100 is occupied)", got)
	}
}

func TestPoolConcurrentAllocate(t *testing.T) {
	p := NewPool(testStore(40200, 40263)) // 32 pairs
	var wg sync.WaitGroup
	got := make(chan *PortPair, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if pair, err := p.allocatePair(); err == nil {
				got <- pair
			}
		}()
	}
	wg.Wait()
	close(got)
	seen := map[int]bool{}
	n := 0
	for pair := range got {
		n++
		if seen[pair.RTPPort()] {
			t.Errorf("port %d allocated twice", pair.RTPPort())
		}
		seen[pair.RTPPort()] = true
		pair.Close()
	}
	if n != 32 {
		t.Errorf("allocated %d pairs, want 32", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./media/ -v`
Expected: FAIL (package doesn't compile — `NewPool` undefined).

- [ ] **Step 3: Implement**

Create `media/portpool.go`:

```go
// Package media implements the RTP/RTCP relay plane: port allocation,
// hardened first-packet latching, and payload-agnostic UDP forwarding
// between the two legs of a call. It knows nothing about SIP or SDP —
// the signaling plane drives it via Pool.Allocate and Session.
package media

import (
	"errors"
	"net"
	"sync"

	"github.com/freesbc/freesbc/config"
)

// ErrPortsExhausted is returned when no free port pair is left in the
// configured range; the signaling plane maps it to 503 (spec §7).
var ErrPortsExhausted = errors.New("media: RTP port range exhausted")

// PortPair is one bound socket pair: RTP on an even port, RTCP on RTP+1.
type PortPair struct {
	RTP  *net.UDPConn
	RTCP *net.UDPConn
}

// RTPPort returns the bound RTP port (the RTCP port is RTPPort()+1).
func (pp *PortPair) RTPPort() int {
	return pp.RTP.LocalAddr().(*net.UDPAddr).Port
}

// Close closes both sockets.
func (pp *PortPair) Close() {
	_ = pp.RTP.Close()
	_ = pp.RTCP.Close()
}

// Pool allocates port pairs from listen.media.port_range. The range is
// read from the config store on every allocation, so a hot-reloaded range
// applies to new calls without disturbing established ones.
type Pool struct {
	store *config.Store

	mu     sync.Mutex
	inUse  map[int]struct{} // RTP (even) ports currently allocated
	cursor int              // next candidate RTP port
}

func NewPool(store *config.Store) *Pool {
	return &Pool{store: store, inUse: make(map[int]struct{})}
}

// allocatePair binds the next free RTP/RTCP pair. Ports occupied by other
// processes are skipped; a full sweep with no free pair returns
// ErrPortsExhausted.
func (p *Pool) allocatePair() (*PortPair, error) {
	media := p.store.Current().Listen.Media
	lo, hi := int(media.PortRange.Min), int(media.PortRange.Max)
	if lo%2 != 0 {
		lo++ // RTP ports are even by convention
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cursor < lo || p.cursor+1 > hi {
		p.cursor = lo
	}
	pairs := (hi - lo + 1) / 2
	for tried := 0; tried < pairs; tried++ {
		port := p.cursor
		p.cursor += 2
		if p.cursor+1 > hi {
			p.cursor = lo
		}
		if _, used := p.inUse[port]; used {
			continue
		}
		pair, err := bindPair(port)
		if err != nil {
			continue // occupied by another process
		}
		p.inUse[port] = struct{}{}
		return pair, nil
	}
	return nil, ErrPortsExhausted
}

// release returns an RTP port to the pool. The caller closes the sockets.
func (p *Pool) release(rtpPort int) {
	p.mu.Lock()
	delete(p.inUse, rtpPort)
	p.mu.Unlock()
}

func bindPair(port int) (*PortPair, error) {
	rtp, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	rtcp, err := net.ListenUDP("udp", &net.UDPAddr{Port: port + 1})
	if err != nil {
		_ = rtp.Close()
		return nil, err
	}
	return &PortPair{RTP: rtp, RTCP: rtcp}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass (race detector on)**

Run: `go test ./media/ -race -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add media/ && git commit -m "feat(media): RTP/RTCP port pool with hot-reload-aware range"
```

---

### Task 4: Latch + session lifecycle

**Files:**
- Create: `media/session.go`
- Test: `media/session_test.go`

**Interfaces:**
- Consumes: `Pool`, `PortPair`, `allocatePair`, `release`, `ErrPortsExhausted` from Task 3.
- Produces (Task 5 and M3 rely on these):
  - `type Side int` with `SideA Side = 0`, `SideB Side = 1`
  - `type LatchMode int` with `LatchStrict LatchMode = iota` (zero value = default), `LatchLoose`
  - `type SessionConfig struct{ Latch [2]LatchMode; Timeout time.Duration }` (zero Timeout = use `listen.media.rtp_timeout` from the current config snapshot)
  - `func (p *Pool) Allocate(cfg SessionConfig) (*Session, error)`
  - `type Session` with `RTPPort(side Side) int`, `SetExpectedRemote(side Side, ip netip.Addr)`, `Done() <-chan struct{}`, `Close() error` (idempotent)
  - package-private `latch` with `setExpected(netip.Addr)`, `accept(*net.UDPAddr) bool`, `target() *net.UDPAddr` — Task 5's relay loops gate every packet through `accept`
  - Session fields Task 5 uses: `pairs [2]*PortPair`, `rtp [2]*latch`, `rtcp [2]*latch`, `timeout time.Duration`, `lastRx atomic.Int64`, `done chan struct{}`

- [ ] **Step 1: Write the failing test**

Create `media/session_test.go`:

```go
package media

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestLatchStrictRejectsWrongSource(t *testing.T) {
	l := &latch{mode: LatchStrict}
	l.setExpected(netip.MustParseAddr("203.0.113.9"))
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4444}
	if l.accept(src) {
		t.Fatal("wrong source must not latch in strict mode")
	}
	if l.target() != nil {
		t.Fatal("latch must remain empty after rejection")
	}
	l.setExpected(netip.MustParseAddr("127.0.0.1"))
	if !l.accept(src) {
		t.Fatal("matching source must latch")
	}
}

func TestLatchStrictWithoutExpectationAcceptsFirst(t *testing.T) {
	l := &latch{mode: LatchStrict}
	if !l.accept(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9}) {
		t.Fatal("strict mode without an expectation must accept the first packet")
	}
}

func TestLatchNeverMoves(t *testing.T) {
	l := &latch{mode: LatchLoose}
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111}
	hijack := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
	if !l.accept(first) {
		t.Fatal("first packet must latch")
	}
	if l.accept(hijack) {
		t.Fatal("a different source must be dropped after latching")
	}
	if got := l.target(); got == nil || got.Port != 1111 {
		t.Fatalf("latch moved: %v", got)
	}
	if !l.accept(first) {
		t.Fatal("the latched source must stay accepted")
	}
}

func TestAllocateAndPorts(t *testing.T) {
	p := NewPool(testStore(40300, 40315))
	s, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer s.Close()
	a, b := s.RTPPort(SideA), s.RTPPort(SideB)
	if a%2 != 0 || b%2 != 0 || a == b {
		t.Errorf("bad ports: A=%d B=%d", a, b)
	}
}

func TestAllocateDefaultsTimeoutFromConfig(t *testing.T) {
	p := NewPool(testStore(40320, 40327))
	s, err := p.Allocate(SessionConfig{}) // zero timeout
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.timeout != 5*time.Minute {
		t.Errorf("timeout = %v, want config default 5m", s.timeout)
	}
}

func TestSessionCloseIdempotentAndReleases(t *testing.T) {
	p := NewPool(testStore(40400, 40403)) // exactly 2 pairs = 1 session
	s, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Allocate(SessionConfig{Timeout: time.Minute}); err == nil {
		t.Fatal("second session must exhaust the 2-pair range")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("Close must be idempotent")
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("Done must be closed after Close")
	}
	s2, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("ports not released by Close: %v", err)
	}
	s2.Close()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./media/ -v`
Expected: FAIL (compile error: `latch`, `Allocate`, `Session` undefined).

- [ ] **Step 3: Implement**

Create `media/session.go`:

```go
package media

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Side identifies one leg of a relayed call.
type Side int

const (
	SideA Side = 0
	SideB Side = 1
)

// LatchMode controls how the first inbound packet of a stream is matched
// against the SDP-signaled source address (spec §3 decision 5).
type LatchMode int

const (
	// LatchStrict (default) requires the first packet's source IP to match
	// the address set via SetExpectedRemote; the port may differ (NAT).
	// With no expectation set, the first packet is accepted from anywhere.
	LatchStrict LatchMode = iota
	// LatchLoose accepts the first packet from any source (hard-NAT peers).
	LatchLoose
)

// latch tracks the remote endpoint of one UDP stream. The first accepted
// packet fixes the remote address; the latch never moves afterwards
// (RTP-hijack hardening).
type latch struct {
	mu       sync.Mutex
	mode     LatchMode
	expected netip.Addr // zero value = no expectation
	remote   *net.UDPAddr
}

func (l *latch) setExpected(ip netip.Addr) {
	l.mu.Lock()
	l.expected = ip
	l.mu.Unlock()
}

// accept reports whether a packet from src may be processed, latching the
// stream to src on the first acceptance.
func (l *latch) accept(src *net.UDPAddr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.remote != nil {
		return l.remote.IP.Equal(src.IP) && l.remote.Port == src.Port
	}
	if l.mode == LatchStrict && l.expected.IsValid() {
		ip, ok := netip.AddrFromSlice(src.IP)
		if !ok || ip.Unmap() != l.expected.Unmap() {
			return false
		}
	}
	l.remote = &net.UDPAddr{
		IP:   append(net.IP(nil), src.IP...),
		Port: src.Port,
		Zone: src.Zone,
	}
	return true
}

// target returns the latched remote, or nil before latching.
func (l *latch) target() *net.UDPAddr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.remote
}

// SessionConfig configures one relayed call.
type SessionConfig struct {
	// Latch is the per-side latching mode (zero value = strict).
	Latch [2]LatchMode
	// Timeout tears the session down after this much silence; zero means
	// use listen.media.rtp_timeout from the current config snapshot.
	Timeout time.Duration
}

// Session is the media half of one call: two port pairs relaying RTP and
// RTCP between side A and side B. Lifecycle: Allocate → SetExpectedRemote
// (from SDP) → Start → Close, or automatic teardown on RTP silence,
// observable via Done. Safe for concurrent use.
type Session struct {
	pool    *Pool
	pairs   [2]*PortPair
	rtp     [2]*latch
	rtcp    [2]*latch
	timeout time.Duration

	lastRx    atomic.Int64 // unix nanos of the last accepted packet
	done      chan struct{}
	closeOnce sync.Once
}

// Allocate binds two port pairs (side A and side B) for one call. The
// caller must Close the session — or rely on silence teardown — to return
// the ports. Returns ErrPortsExhausted when the range is full.
func (p *Pool) Allocate(cfg SessionConfig) (*Session, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = p.store.Current().Listen.Media.RTPTimeout.Std()
	}
	a, err := p.allocatePair()
	if err != nil {
		return nil, err
	}
	b, err := p.allocatePair()
	if err != nil {
		a.Close()
		p.release(a.RTPPort())
		return nil, err
	}
	s := &Session{
		pool:    p,
		pairs:   [2]*PortPair{a, b},
		timeout: cfg.Timeout,
		done:    make(chan struct{}),
	}
	for side := range s.pairs {
		s.rtp[side] = &latch{mode: cfg.Latch[side]}
		s.rtcp[side] = &latch{mode: cfg.Latch[side]}
	}
	return s, nil
}

// RTPPort returns the local RTP port of one side (RTCP is RTP+1); the
// signaling plane writes these into rewritten SDP.
func (s *Session) RTPPort(side Side) int { return s.pairs[side].RTPPort() }

// SetExpectedRemote records the SDP-signaled media source IP for one side;
// strict latching checks the first packet against it.
func (s *Session) SetExpectedRemote(side Side, ip netip.Addr) {
	s.rtp[side].setExpected(ip)
	s.rtcp[side].setExpected(ip)
}

// Done is closed when the session ends (Close or silence timeout).
func (s *Session) Done() <-chan struct{} { return s.done }

// Close tears the session down and returns its ports to the pool.
// Idempotent and safe to call from any goroutine.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		for _, pp := range s.pairs {
			pp.Close()
		}
		s.pool.release(s.pairs[SideA].RTPPort())
		s.pool.release(s.pairs[SideB].RTPPort())
		close(s.done)
	})
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass (race detector on)**

Run: `go test ./media/ -race -v`
Expected: PASS (all media tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add media/ && git commit -m "feat(media): session lifecycle with hardened first-packet latching"
```

---

### Task 5: Relay loops + silence watchdog

**Files:**
- Create: `media/relay.go`
- Test: `media/relay_test.go`

**Interfaces:**
- Consumes: `Session` (fields `pairs`, `rtp`, `rtcp`, `timeout`, `lastRx`, `done`), `latch.accept`/`target`, `SideA`/`SideB` from Task 4.
- Produces (M3 relies on this): `func (s *Session) Start()` — launches four forwarding loops (RTP and RTCP, both directions) plus the silence watchdog. After Start, packets accepted on one side are forwarded to the other side's latched remote, sourced from the other side's own socket (so remotes see the port they send to). Panic in a loop kills only that session (spec §7).

- [ ] **Step 1: Write the failing test**

Create `media/relay_test.go`:

```go
package media

import (
	"net"
	"testing"
	"time"
)

func newLooseSession(t *testing.T, minPort, maxPort int, timeout time.Duration) *Session {
	t.Helper()
	p := NewPool(testStore(minPort, maxPort))
	s, err := p.Allocate(SessionConfig{
		Latch:   [2]LatchMode{LatchLoose, LatchLoose},
		Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func dialSide(t *testing.T, s *Session, side Side) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(side),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// pump sends payload from src until dst receives exactly it, tolerating
// earlier packets still in flight. Both endpoints must already have sent
// one packet so their side is latched.
func pump(t *testing.T, src, dst *net.UDPConn, payload string) {
	t.Helper()
	buf := make([]byte, 1500)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := src.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		_ = dst.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := dst.Read(buf)
		if err == nil && string(buf[:n]) == payload {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("packet %q never forwarded", payload)
		}
	}
}

func TestRelayForwardsBothDirections(t *testing.T) {
	s := newLooseSession(t, 41000, 41015, time.Minute)
	s.Start()
	ea := dialSide(t, s, SideA)
	eb := dialSide(t, s, SideB)
	// First packet from each endpoint latches its side.
	if _, err := ea.Write([]byte("latch-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := eb.Write([]byte("latch-b")); err != nil {
		t.Fatal(err)
	}
	pump(t, ea, eb, "ping-from-a")
	pump(t, eb, ea, "pong-from-b")
}

func TestRelayDropsHijackPackets(t *testing.T) {
	s := newLooseSession(t, 41100, 41115, time.Minute)
	s.Start()
	ea := dialSide(t, s, SideA)
	eb := dialSide(t, s, SideB)
	if _, err := ea.Write([]byte("latch-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := eb.Write([]byte("latch-b")); err != nil {
		t.Fatal(err)
	}
	pump(t, ea, eb, "establish")

	// Same IP, different source port: must be dropped, latch must not move.
	hijacker := dialSide(t, s, SideA)
	if _, err := hijacker.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = eb.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		n, err := eb.Read(buf)
		if err != nil {
			break // drained: nothing (more) arrived
		}
		if string(buf[:n]) == "evil" {
			t.Fatal("hijack packet was forwarded")
		}
	}
	// The legitimate stream still works.
	pump(t, ea, eb, "still-alive")
}

func TestRelaySilenceTimeoutReleasesPorts(t *testing.T) {
	p := NewPool(testStore(41200, 41203)) // exactly one session's worth
	s, err := p.Allocate(SessionConfig{
		Latch:   [2]LatchMode{LatchLoose, LatchLoose},
		Timeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not tear down on RTP silence")
	}
	s2, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("ports not released after silence teardown: %v", err)
	}
	s2.Close()
}

func TestRelayActivityDefersTimeout(t *testing.T) {
	s := newLooseSession(t, 41250, 41257, 500*time.Millisecond)
	s.Start()
	ea := dialSide(t, s, SideA)
	// Keep the session alive for ~3 timeout periods with steady traffic.
	stop := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(stop) {
		if _, err := ea.Write([]byte("keepalive")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.Done():
			t.Fatal("session timed out despite steady traffic")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./media/ -run TestRelay -v`
Expected: FAIL (compile error: `Start` undefined).

- [ ] **Step 3: Implement**

Create `media/relay.go`:

```go
package media

import "time"

// Start launches the four forwarding loops (RTP and RTCP in both
// directions) and the silence watchdog. Call at most once, after any
// SetExpectedRemote calls for strict latching.
func (s *Session) Start() {
	s.lastRx.Store(time.Now().UnixNano())
	s.forward(SideA, SideB, true)
	s.forward(SideB, SideA, true)
	s.forward(SideA, SideB, false)
	s.forward(SideB, SideA, false)
	go s.watchdog()
}

// forward starts one read loop copying packets that arrive on the `from`
// side (gated by its latch) to the `to` side's latched remote, sending
// from the `to` side's own socket so the remote sees the port it already
// talks to. rtpKind selects the RTP or RTCP socket/latch of both sides.
// The loop exits when its socket is closed. A panic kills only this
// session, never the process (spec §7).
func (s *Session) forward(from, to Side, rtpKind bool) {
	in, inLatch := s.pairs[from].RTCP, s.rtcp[from]
	out, outLatch := s.pairs[to].RTCP, s.rtcp[to]
	if rtpKind {
		in, inLatch = s.pairs[from].RTP, s.rtp[from]
		out, outLatch = s.pairs[to].RTP, s.rtp[to]
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				_ = s.Close()
			}
		}()
		buf := make([]byte, 1500)
		for {
			n, src, err := in.ReadFromUDP(buf)
			if err != nil {
				return // socket closed (session teardown)
			}
			if !inLatch.accept(src) {
				continue // pre-latch source mismatch, or post-latch hijack
			}
			s.lastRx.Store(time.Now().UnixNano())
			if dst := outLatch.target(); dst != nil {
				_, _ = out.WriteToUDP(buf[:n], dst)
			}
		}
	}()
}

// watchdog tears the session down after `timeout` of RTP silence
// (spec §7: half-dead calls are reclaimed automatically).
func (s *Session) watchdog() {
	interval := s.timeout / 4
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			last := time.Unix(0, s.lastRx.Load())
			if time.Since(last) > s.timeout {
				_ = s.Close()
				return
			}
		}
	}
}
```

- [ ] **Step 4: Run the media suite (race detector on)**

Run: `go test ./media/ -race -v`
Expected: PASS (all media tests, no races). The relay tests are timing-based with generous margins; if one flakes on a loaded machine, re-run once before investigating.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add media/ && git commit -m "feat(media): UDP relay loops with latching gate and silence watchdog"
```

---

### Task 6: Wire media pool into `run()` + CLI polish + docs + full verification

Also closes two M1-triaged backlog items: top-level `-h`/`--help` currently exits 2 via the unknown-subcommand path, and the config-watcher goroutine is fire-and-forget on shutdown.

**Files:**
- Modify: `main.go` (main + run functions)
- Modify: `README.md` (roadmap row M2)

**Interfaces:**
- Consumes: `media.NewPool(store *config.Store) *Pool` from Task 3.
- Produces: `run()` owns a `*media.Pool`; M3's signaling plane will take it as a constructor argument. Shutdown now waits for the watcher goroutine (the pattern M3+ planes must join).

- [ ] **Step 1: Wire the pool, help flag, and coordinated shutdown**

In `main.go`, add `"github.com/freesbc/freesbc/media"` and `"sync"` to the imports.

In `main()`, immediately after `cmd := os.Args[1]`, add:

```go
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return
	}
```

In `run()`, replace the watcher goroutine block and the comment block `// M2+: media port pool, ...` so the function reads:

```go
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := config.Watch(ctx, cfgPath, store, log); err != nil && ctx.Err() == nil {
			log.Error("config watcher exited", "err", err)
		}
	}()

	pool := media.NewPool(store)
	_ = pool // handed to the signaling plane in M3

	mediaCfg := store.Current().Listen.Media
	log.Info("media plane ready",
		"port_range", fmt.Sprintf("%d-%d", mediaCfg.PortRange.Min, mediaCfg.PortRange.Max),
		"rtp_timeout", mediaCfg.RTPTimeout.Std())

	// M3+: SIP listeners, shield, and admin API start here, each reading
	// snapshots via store.Current().

	log.Info("freesbc started",
		"config", cfgPath,
		"peers", len(store.Current().Peers),
		"routes", len(store.Current().Routes))

	<-ctx.Done()
	log.Info("shutting down")
	wg.Wait()
	return nil
```

(The `cfg, err := config.Load(...)`, store creation, and `signal.NotifyContext` lines above this block are unchanged.)

- [ ] **Step 2: Update the README roadmap**

In `README.md`, change the M2 row of the roadmap table:

```markdown
| M2 | Media plane: RTP port pool, relay engine, latching hardening | ✅ done |
| M3 | Signaling core: SIP server, B2BUA, SDP rewrite, routing — first end-to-end call | next |
```

(Only these two rows change: M2 gains `✅ done`, `next` moves to M3.)

- [ ] **Step 3: Full verification + smoke test**

```bash
go vet ./... && go test ./... -race
```

Expected: vet clean, all config + media tests PASS.

```bash
go build -o freesbc . && CARRIER_A_PASS=test ./freesbc run -c sbc.example.yaml & PID=$!
sleep 1; kill -TERM $PID; wait $PID; echo "exit=$?"
```

Expected: startup logs include `freesbc started` AND `media plane ready ... port_range=16384-32768 rtp_timeout=5m0s`, then `shutting down`, `exit=0`.

```bash
./freesbc --help; echo "exit=$?"
```

Expected: usage text, `exit=0`.

- [ ] **Step 4: Commit**

```bash
gofmt -l . && git add main.go README.md && git commit -m "feat: wire media pool into run(); mark M2 done in roadmap"
```

---

## Spec Coverage (M2 slice)

| Spec requirement | Task |
|---|---|
| §4 `media/portpool.go` — RTP 端口池分配/回收 | 3 |
| §4 `media/relay.go` — UDP 转发引擎（per-call goroutines） | 5 |
| §3 decision 5 — latching 加固（pre-media only, source-IP check, never re-latch, strict/loose per peer） | 2 (config), 4 (logic), 5 (enforcement) |
| §6 step 10 — 双向媒体转发 + 首包 latching | 5 |
| §7 — 媒体端口耗尽 → caller error (503 mapping in M3) | 3 (`ErrPortsExhausted`) |
| §7 — per-call panic recover, call dies, process survives | 5 (`forward` recover) |
| §7 — 半死呼叫 RTP 静默超时（默认 5 分钟）自动拆线 | 2 (config), 5 (watchdog) |
| §3 — 模块接口 sig→media：Allocate/Session.Close | 4 (deviation from sketch documented in Global Constraints) |
| M1 backlog — quoted scalars (Important), doubled error prefix | 1 |
| M1 backlog — top-level `-h` exit code, watcher shutdown coordination | 6 |

Deferred (documented in header): STUN for `public_ip: auto` (M3), SRTP (M5), metrics (M7), perf/batch syscalls (M3+ benchmark), `media/srtp.go` (M5).

## Post-Implementation Amendments (2026-07-15, final review)

- Relay panic recovery now logs the panic value and `debug.Stack()` via `slog` before killing the session (`recoverRelayPanic`, with an injection test) — silent call drops were the review's Important #1.

## Carry-over for M3 (from final review)

- **M3 DESIGN DECISION — DECIDED 2026-07-15 (user-confirmed, recorded in spec §3 decision 5):** hybrid of (a) and (b). Initial media: strict per-side arming — a strict side drops everything until the signaling plane arms it via `SetExpectedRemote` (this changes the pinned `TestLatchStrictWithoutExpectationAcceptsFirst` semantics; that change is authorized). Subsequent media changes: authorized re-latch (`Relatch(side, ip)`) invoked only from the SIP/SDP state machine on re-INVITE/hold-resume; local ports persist across re-INVITEs. Implemented as M3's first task.
- Put the peer `media_latch` string → `LatchMode` converter in the `media` package (`ParseLatchMode`) when M3 maps peer config to sessions.
- Concurrent `Allocate` at the exhaustion boundary can doubly fail where serial would succeed once (two-lock acquisition); fix with `allocatePairs(n)` under one lock if 503 spikes matter.
- Relay buffer is 1500 bytes — larger datagrams are truncated, not dropped; bump or document MTU assumption (revisit for SRTP in M5).
- RTCP traffic defers the "RTP silence" watchdog — decide intended semantics, document.
- `Start` has no call-twice guard (M3 owns the single call site; one-line `sync.Once` insurance).
- Test-coverage debt: panic-injection test landed; still open — RTCP-path relay test, hot-reload range pickup test, second-pair unwind regression test, `media_latch: loose` positive validate case (fold into M3's end-to-end work).
