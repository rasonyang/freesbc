# FreeSBC M1 — Config Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single Go binary `freesbc` that loads, validates, env-expands, and hot-reloads a declarative `sbc.yaml`, exposing lock-free config snapshots to future modules.

**Architecture:** All configuration lives in one YAML file (single source of truth). The `config` package parses it strictly (unknown keys are errors, with line numbers), applies defaults, validates cross-references (routes → peers, regexes, CIDRs), and publishes immutable `*Config` snapshots through an `atomic.Pointer` store. An fsnotify watcher revalidates on file change and atomically swaps in the new config; a bad config keeps the old one running — the process never dies from a bad reload.

**Tech Stack:** Go ≥ 1.22, `github.com/goccy/go-yaml` (strict parsing + line-numbered errors), `github.com/fsnotify/fsnotify` (hot reload), stdlib `log/slog`, `net/netip`, `sync/atomic`.

**Roadmap context:** This is Plan 1 of the FreeSBC MVP (spec: `freesbc-allinone-design.md`). Later milestones: M2 media plane, M3 signaling core (B2BUA), M4 trunk interop (REGISTER/timers/PRACK/SRV), M5 SRTP-SDES, M6 shield, M7 admin/WebUI/metrics. Each gets its own plan.

## Global Constraints

- Go module path: `github.com/freesbc/freesbc` (Go ≥ 1.22 in go.mod).
- Dependencies allowed in this plan: `github.com/goccy/go-yaml`, `github.com/fsnotify/fsnotify` — nothing else beyond stdlib. (MVP-wide whitelist per spec §4: sipgo, pion/{srtp,rtp,sdp}, fsnotify, goccy/go-yaml, prometheus/client_golang. No database, no Redis, no web framework.)
- Bad config at startup → process exits non-zero with an error naming the line/field. Bad config at hot reload → keep old config, log the error, never crash (spec §7).
- Runtime state is memory-only; `sbc.yaml` is the only persisted artifact (spec §3).
- `${ENV_VAR}` references in YAML are expanded into the runtime config only; the file on disk is never rewritten with expanded secrets (spec §5).
- All code, comments, and log messages in English. Tests use only stdlib `testing` (no assertion libraries).
- Every task: run `gofmt -l .` before committing — output must be empty.

---

### Task 1: Module scaffold + config value types

**Files:**
- Create: `go.mod` (via `go mod init`)
- Create: `config/types.go`
- Test: `config/types_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `type Duration time.Duration` with `func (d *Duration) UnmarshalYAML(b []byte) error` and `func (d Duration) Std() time.Duration`
  - `type PortRange struct{ Min, Max uint16 }` with `func (p *PortRange) UnmarshalYAML(b []byte) error`
  - `type SIPListen struct{ Transport, Host string; Port int }` with `func (s *SIPListen) UnmarshalYAML(b []byte) error`
  - `type RateLimit struct{ Rate int; Interval time.Duration; PerIP bool }` and `func ParseRateLimit(s string) (RateLimit, error)`

- [ ] **Step 1: Initialize the module and fetch dependencies**

```bash
cd /Users/rasonyang/workspaces/cc/freesbc
go mod init github.com/freesbc/freesbc
go get github.com/goccy/go-yaml@latest
go get github.com/fsnotify/fsnotify@latest
```

Expected: `go.mod` created with both requires.

- [ ] **Step 2: Write the failing tests**

Create `config/types_test.go`:

```go
package config

import (
	"testing"
	"time"
)

func TestDurationUnmarshalYAML(t *testing.T) {
	var d Duration
	if err := d.UnmarshalYAML([]byte("90s")); err != nil {
		t.Fatalf("unmarshal 90s: %v", err)
	}
	if d.Std() != 90*time.Second {
		t.Errorf("got %v, want 90s", d.Std())
	}
	if err := d.UnmarshalYAML([]byte("not-a-duration")); err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestPortRangeUnmarshalYAML(t *testing.T) {
	var p PortRange
	if err := p.UnmarshalYAML([]byte("16384-32768")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Min != 16384 || p.Max != 32768 {
		t.Errorf("got %d-%d, want 16384-32768", p.Min, p.Max)
	}
	for _, bad := range []string{"16384", "32768-16384", "0-70000", "a-b"} {
		if err := p.UnmarshalYAML([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestSIPListenUnmarshalYAML(t *testing.T) {
	var s SIPListen
	if err := s.UnmarshalYAML([]byte("udp://0.0.0.0:5060")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Transport != "udp" || s.Host != "0.0.0.0" || s.Port != 5060 {
		t.Errorf("got %+v", s)
	}
	if err := s.UnmarshalYAML([]byte("tls://0.0.0.0:5061")); err != nil {
		t.Fatalf("tls listener: %v", err)
	}
	for _, bad := range []string{"sctp://0.0.0.0:5060", "udp://nohost", "5060"} {
		if err := s.UnmarshalYAML([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestParseRateLimit(t *testing.T) {
	rl, err := ParseRateLimit("20/s per_ip")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rl.Rate != 20 || rl.Interval != time.Second || !rl.PerIP {
		t.Errorf("got %+v", rl)
	}
	rl, err = ParseRateLimit("100/m")
	if err != nil {
		t.Fatalf("parse global: %v", err)
	}
	if rl.Rate != 100 || rl.Interval != time.Minute || rl.PerIP {
		t.Errorf("got %+v", rl)
	}
	for _, bad := range []string{"", "20", "0/s", "20/d", "20/s per_call"} {
		if _, err := ParseRateLimit(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./config/ -v`
Expected: FAIL (compile error: undefined types — the package doesn't exist yet).

- [ ] **Step 4: Write the implementation**

Create `config/types.go`:

```go
// Package config loads, validates, and hot-reloads the sbc.yaml
// configuration file — the single source of truth for FreeSBC.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Duration parses YAML scalars like "60s" or "1h" via time.ParseDuration.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", string(b), err)
	}
	*d = Duration(v)
	return nil
}

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// PortRange is an inclusive UDP port range, written as "16384-32768".
type PortRange struct {
	Min, Max uint16
}

func (p *PortRange) UnmarshalYAML(b []byte) error {
	s := strings.TrimSpace(string(b))
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return fmt.Errorf("invalid port range %q: want \"min-max\"", s)
	}
	minP, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port range %q: %w", s, err)
	}
	maxP, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port range %q: %w", s, err)
	}
	if minP == 0 || minP >= maxP {
		return fmt.Errorf("invalid port range %q: min must be >0 and < max", s)
	}
	p.Min, p.Max = uint16(minP), uint16(maxP)
	return nil
}

// SIPListen is one signaling listener, written as "udp://0.0.0.0:5060".
type SIPListen struct {
	Transport string // "udp", "tcp", or "tls"
	Host      string
	Port      int
}

func (s *SIPListen) UnmarshalYAML(b []byte) error {
	raw := strings.TrimSpace(string(b))
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid listener %q: %w", raw, err)
	}
	switch u.Scheme {
	case "udp", "tcp", "tls":
	default:
		return fmt.Errorf("invalid listener %q: transport must be udp, tcp, or tls", raw)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("invalid listener %q: %w", raw, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid listener %q: bad port", raw)
	}
	s.Transport, s.Host, s.Port = u.Scheme, host, port
	return nil
}

// RateLimit is the parsed form of shield.rate_limit, e.g. "20/s per_ip".
type RateLimit struct {
	Rate     int
	Interval time.Duration
	PerIP    bool
}

// ParseRateLimit parses "<n>/<s|m|h>[ per_ip]".
func ParseRateLimit(s string) (RateLimit, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 || len(fields) > 2 {
		return RateLimit{}, fmt.Errorf("invalid rate limit %q: want \"<n>/<s|m|h> [per_ip]\"", s)
	}
	var rl RateLimit
	if len(fields) == 2 {
		if fields[1] != "per_ip" {
			return RateLimit{}, fmt.Errorf("invalid rate limit %q: unknown scope %q", s, fields[1])
		}
		rl.PerIP = true
	}
	numStr, unit, ok := strings.Cut(fields[0], "/")
	if !ok {
		return RateLimit{}, fmt.Errorf("invalid rate limit %q: missing \"/\"", s)
	}
	n, err := strconv.Atoi(numStr)
	if err != nil || n <= 0 {
		return RateLimit{}, fmt.Errorf("invalid rate limit %q: rate must be a positive integer", s)
	}
	rl.Rate = n
	switch unit {
	case "s":
		rl.Interval = time.Second
	case "m":
		rl.Interval = time.Minute
	case "h":
		rl.Interval = time.Hour
	default:
		return RateLimit{}, fmt.Errorf("invalid rate limit %q: unit must be s, m, or h", s)
	}
	return rl, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./config/ -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
gofmt -l . && git add go.mod go.sum config/ && git commit -m "feat(config): module scaffold + YAML value types (Duration, PortRange, SIPListen, RateLimit)"
```

---

### Task 2: Config schema structs + defaults

**Files:**
- Create: `config/schema.go`
- Test: `config/schema_test.go`

**Interfaces:**
- Consumes: `Duration`, `PortRange`, `SIPListen` from Task 1.
- Produces (later tasks and all future modules rely on these exact names):
  - `type Config struct{ Listen ListenConfig; Peers map[string]*Peer; Routes []*Route; Shield ShieldConfig; Admin *AdminConfig }`
  - `type ListenConfig struct{ SIP []SIPListen; Media MediaConfig }`
  - `type MediaConfig struct{ PortRange PortRange; PublicIP string }`
  - `type Peer struct{ Address, Transport string; Auth *PeerAuth; Register bool; AllowedIPs []string }` plus method `AllowsIP(netip.Addr) bool` (compiled in Task 3)
  - `type PeerAuth struct{ Username, Password string }`
  - `type Route struct{ Name, From string; Match *RouteMatch; Transform *RouteTransform; To []string }` plus method `CompiledMatch() *regexp.Regexp` (compiled in Task 3)
  - `type ShieldConfig struct{ RateLimit string; AutoBan AutoBan; NFTables string }`
  - `type AutoBan struct{ Failures int; Window Duration; Duration Duration }`
  - `type AdminConfig struct{ Listen string; Auth AdminAuth }`, `type AdminAuth struct{ Username, PasswordHash string }`
  - `func withDefaults(c *Config)` (package-private, called by the loader in Task 4)

- [ ] **Step 1: Write the failing test**

Create `config/schema_test.go`:

```go
package config

import (
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

func TestSchemaUnmarshalFullExample(t *testing.T) {
	src := `
listen:
  sip:
    - udp://0.0.0.0:5060
    - tls://0.0.0.0:5061
  media:
    port_range: 16384-32768
    public_ip: auto
peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    transport: udp
    auth: { username: acct01, password: secret }
    register: true
    allowed_ips: [203.0.113.0/24]
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a]
  - name: inbound
    from: carrier-a
    to: [internal-pbx]
shield:
  rate_limit: 20/s per_ip
  auto_ban: { failures: 5, window: 60s, duration: 1h }
  nftables: auto
admin:
  listen: 127.0.0.1:8080
  auth: { username: admin, password_hash: "x" }
`
	var c Config
	if err := yaml.UnmarshalWithOptions([]byte(src), &c, yaml.Strict()); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(c.Listen.SIP) != 2 || c.Listen.SIP[1].Transport != "tls" {
		t.Errorf("listen.sip: %+v", c.Listen.SIP)
	}
	ca := c.Peers["carrier-a"]
	if ca == nil || !ca.Register || ca.Auth == nil || ca.Auth.Username != "acct01" {
		t.Errorf("carrier-a: %+v", ca)
	}
	if len(c.Routes) != 2 || c.Routes[0].Match.To != `^9(\d+)$` || c.Routes[0].Transform.To != "$1" {
		t.Errorf("routes: %+v, %+v", c.Routes[0], c.Routes[1])
	}
	if c.Shield.AutoBan.Window.Std() != 60*time.Second {
		t.Errorf("auto_ban.window: %v", c.Shield.AutoBan.Window.Std())
	}
	if c.Admin == nil || c.Admin.Listen != "127.0.0.1:8080" {
		t.Errorf("admin: %+v", c.Admin)
	}
}

func TestWithDefaults(t *testing.T) {
	c := &Config{Peers: map[string]*Peer{"p": {Address: "10.0.0.1:5060"}}}
	withDefaults(c)
	if c.Peers["p"].Transport != "udp" {
		t.Errorf("peer transport default: %q", c.Peers["p"].Transport)
	}
	if c.Listen.Media.PortRange.Min != 16384 || c.Listen.Media.PortRange.Max != 32768 {
		t.Errorf("port range default: %+v", c.Listen.Media.PortRange)
	}
	if c.Listen.Media.PublicIP != "auto" {
		t.Errorf("public_ip default: %q", c.Listen.Media.PublicIP)
	}
	if c.Shield.RateLimit != "20/s per_ip" {
		t.Errorf("rate_limit default: %q", c.Shield.RateLimit)
	}
	if c.Shield.AutoBan.Failures != 5 || c.Shield.AutoBan.Window.Std() != 60*time.Second || c.Shield.AutoBan.Duration.Std() != time.Hour {
		t.Errorf("auto_ban default: %+v", c.Shield.AutoBan)
	}
	if c.Shield.NFTables != "auto" {
		t.Errorf("nftables default: %q", c.Shield.NFTables)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run 'TestSchema|TestWithDefaults' -v`
Expected: FAIL (compile error: undefined `Config`, `withDefaults`).

- [ ] **Step 3: Write the implementation**

Create `config/schema.go`:

```go
package config

import (
	"net/netip"
	"regexp"
	"time"
)

// Config is the root of sbc.yaml. Snapshots are immutable once published:
// never mutate a *Config after handing it to a Store.
type Config struct {
	Listen ListenConfig     `yaml:"listen"`
	Peers  map[string]*Peer `yaml:"peers"`
	Routes []*Route         `yaml:"routes"`
	Shield ShieldConfig     `yaml:"shield"`
	Admin  *AdminConfig     `yaml:"admin"`
}

type ListenConfig struct {
	SIP   []SIPListen `yaml:"sip"`
	Media MediaConfig `yaml:"media"`
}

type MediaConfig struct {
	PortRange PortRange `yaml:"port_range"`
	PublicIP  string    `yaml:"public_ip"` // "auto" (STUN-detected) or a literal IP
}

// Peer is a SIP trunk counterpart (carrier or PBX).
type Peer struct {
	Address    string    `yaml:"address"`
	Transport  string    `yaml:"transport"` // udp (default), tcp, tls
	Auth       *PeerAuth `yaml:"auth"`
	Register   bool      `yaml:"register"` // outbound REGISTER to this peer
	AllowedIPs []string  `yaml:"allowed_ips"`

	allowedNets []netip.Prefix // compiled by Validate
}

// AllowsIP reports whether addr matches one of the peer's allowed_ips
// prefixes. Only valid after Validate has run.
func (p *Peer) AllowsIP(addr netip.Addr) bool {
	for _, n := range p.allowedNets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

type PeerAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Route is one routing rule; first match wins, list order is failover order.
type Route struct {
	Name      string          `yaml:"name"`
	From      string          `yaml:"from"`
	Match     *RouteMatch     `yaml:"match"`
	Transform *RouteTransform `yaml:"transform"`
	To        []string        `yaml:"to"`

	matchTo *regexp.Regexp // compiled by Validate
}

// CompiledMatch returns the compiled match.to regex, or nil when the route
// has no match clause. Only valid after Validate has run.
func (r *Route) CompiledMatch() *regexp.Regexp { return r.matchTo }

type RouteMatch struct {
	To string `yaml:"to"`
}

type RouteTransform struct {
	To string `yaml:"to"`
}

type ShieldConfig struct {
	RateLimit string  `yaml:"rate_limit"`
	AutoBan   AutoBan `yaml:"auto_ban"`
	NFTables  string  `yaml:"nftables"` // auto, on, off
}

type AutoBan struct {
	Failures int      `yaml:"failures"`
	Window   Duration `yaml:"window"`
	Duration Duration `yaml:"duration"`
}

type AdminConfig struct {
	Listen string    `yaml:"listen"`
	Auth   AdminAuth `yaml:"auth"`
}

type AdminAuth struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// withDefaults fills spec-defined defaults on a freshly parsed Config.
func withDefaults(c *Config) {
	if c.Listen.Media.PortRange == (PortRange{}) {
		c.Listen.Media.PortRange = PortRange{Min: 16384, Max: 32768}
	}
	if c.Listen.Media.PublicIP == "" {
		c.Listen.Media.PublicIP = "auto"
	}
	for _, p := range c.Peers {
		if p.Transport == "" {
			p.Transport = "udp"
		}
	}
	if c.Shield.RateLimit == "" {
		c.Shield.RateLimit = "20/s per_ip"
	}
	if c.Shield.AutoBan.Failures == 0 {
		c.Shield.AutoBan.Failures = 5
	}
	if c.Shield.AutoBan.Window == 0 {
		c.Shield.AutoBan.Window = Duration(60 * time.Second)
	}
	if c.Shield.AutoBan.Duration == 0 {
		c.Shield.AutoBan.Duration = Duration(time.Hour)
	}
	if c.Shield.NFTables == "" {
		c.Shield.NFTables = "auto"
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./config/ -v`
Expected: PASS (all tests, including Task 1's).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ && git commit -m "feat(config): schema structs and spec defaults"
```

---

### Task 3: Validation

**Files:**
- Create: `config/validate.go`
- Test: `config/validate_test.go`

**Interfaces:**
- Consumes: `Config`, `Peer`, `Route` from Task 2; `ParseRateLimit` from Task 1.
- Produces: `func (c *Config) Validate() error` — aggregates ALL problems into one error (newline-separated), compiles `Peer.allowedNets` and `Route.matchTo` as a side effect. Task 4's loader calls this.

- [ ] **Step 1: Write the failing test**

Create `config/validate_test.go`:

```go
package config

import (
	"net/netip"
	"strings"
	"testing"
)

// validConfig returns a minimal config that passes Validate.
func validConfig() *Config {
	c := &Config{
		Listen: ListenConfig{SIP: []SIPListen{{Transport: "udp", Host: "0.0.0.0", Port: 5060}}},
		Peers: map[string]*Peer{
			"pbx": {Address: "10.0.0.10:5060", AllowedIPs: []string{"10.0.0.0/8"}},
		},
		Routes: []*Route{{Name: "in", From: "pbx", To: []string{"pbx"}}},
	}
	withDefaults(c)
	return c
}

func TestValidateOK(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateCompilesAllowedIPs(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.Peers["pbx"]
	if !p.AllowsIP(netip.MustParseAddr("10.1.2.3")) {
		t.Error("10.1.2.3 should be allowed")
	}
	if p.AllowsIP(netip.MustParseAddr("192.168.1.1")) {
		t.Error("192.168.1.1 should not be allowed")
	}
}

func TestValidateBareIPBecomesHostPrefix(t *testing.T) {
	c := validConfig()
	c.Peers["pbx"].AllowedIPs = []string{"203.0.113.7"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.Peers["pbx"].AllowsIP(netip.MustParseAddr("203.0.113.7")) {
		t.Error("bare IP should allow itself")
	}
	if c.Peers["pbx"].AllowsIP(netip.MustParseAddr("203.0.113.8")) {
		t.Error("bare IP must not allow neighbors")
	}
}

func TestValidateCompilesMatchRegex(t *testing.T) {
	c := validConfig()
	c.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	re := c.Routes[0].CompiledMatch()
	if re == nil || !re.MatchString("9123") || re.MatchString("8123") {
		t.Errorf("compiled regex wrong: %v", re)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"no listeners", func(c *Config) { c.Listen.SIP = nil }, "listen.sip"},
		{"low port range", func(c *Config) { c.Listen.Media.PortRange = PortRange{Min: 80, Max: 90} }, "port_range"},
		{"bad public ip", func(c *Config) { c.Listen.Media.PublicIP = "not-an-ip" }, "public_ip"},
		{"no peers", func(c *Config) { c.Peers = nil }, "peers"},
		{"peer no address", func(c *Config) { c.Peers["pbx"].Address = "" }, "pbx: address"},
		{"peer bad transport", func(c *Config) { c.Peers["pbx"].Transport = "sctp" }, "transport"},
		{"register without auth", func(c *Config) { c.Peers["pbx"].Register = true }, "requires auth"},
		{"bad cidr", func(c *Config) { c.Peers["pbx"].AllowedIPs = []string{"10.0.0.0/99"} }, "allowed_ips"},
		{"route no name", func(c *Config) { c.Routes[0].Name = "" }, "name required"},
		{"route unknown from", func(c *Config) { c.Routes[0].From = "ghost" }, `unknown peer "ghost"`},
		{"route empty to", func(c *Config) { c.Routes[0].To = nil }, "to:"},
		{"route unknown to", func(c *Config) { c.Routes[0].To = []string{"ghost"} }, `unknown peer "ghost"`},
		{"bad regex", func(c *Config) { c.Routes[0].Match = &RouteMatch{To: "("} }, "match.to"},
		{"transform without match", func(c *Config) { c.Routes[0].Transform = &RouteTransform{To: "$1"} }, "transform.to requires match.to"},
		{"bad rate limit", func(c *Config) { c.Shield.RateLimit = "lots" }, "rate_limit"},
		{"bad nftables", func(c *Config) { c.Shield.NFTables = "maybe" }, "nftables"},
		{"bad admin listen", func(c *Config) { c.Admin = &AdminConfig{Listen: "nope"} }, "admin.listen"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestValidateAggregatesAllErrors(t *testing.T) {
	c := validConfig()
	c.Listen.SIP = nil
	c.Routes[0].From = "ghost"
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "listen.sip") || !strings.Contains(msg, "ghost") {
		t.Errorf("expected both errors reported, got: %q", msg)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run TestValidate -v`
Expected: FAIL (compile error: `Validate` undefined).

- [ ] **Step 3: Write the implementation**

Create `config/validate.go`:

```go
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Validate checks cross-references and value constraints, collecting every
// problem instead of stopping at the first. On success it also compiles
// derived state (peer allowed-IP prefixes, route match regexes).
func (c *Config) Validate() error {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if len(c.Listen.SIP) == 0 {
		fail("listen.sip: at least one listener required")
	}
	if pr := c.Listen.Media.PortRange; pr.Min < 1024 {
		fail("listen.media.port_range: must start at or above 1024, got %d-%d", pr.Min, pr.Max)
	}
	if pub := c.Listen.Media.PublicIP; pub != "auto" {
		if _, err := netip.ParseAddr(pub); err != nil {
			fail("listen.media.public_ip: %q is neither \"auto\" nor a valid IP", pub)
		}
	}

	if len(c.Peers) == 0 {
		fail("peers: at least one peer required")
	}
	for name, p := range c.Peers {
		if p.Address == "" {
			fail("peers.%s: address required", name)
		}
		switch p.Transport {
		case "udp", "tcp", "tls":
		default:
			fail("peers.%s: transport must be udp, tcp, or tls, got %q", name, p.Transport)
		}
		if p.Register && p.Auth == nil {
			fail("peers.%s: register: true requires auth credentials", name)
		}
		p.allowedNets = nil
		for _, s := range p.AllowedIPs {
			pfx, err := parsePrefixOrAddr(s)
			if err != nil {
				fail("peers.%s.allowed_ips: %v", name, err)
				continue
			}
			p.allowedNets = append(p.allowedNets, pfx)
		}
	}

	for i, r := range c.Routes {
		label := r.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
			fail("routes[%d]: name required", i)
		}
		if _, ok := c.Peers[r.From]; !ok {
			fail("routes.%s: from: unknown peer %q", label, r.From)
		}
		if len(r.To) == 0 {
			fail("routes.%s: to: at least one target peer required", label)
		}
		for _, t := range r.To {
			if _, ok := c.Peers[t]; !ok {
				fail("routes.%s: to: unknown peer %q", label, t)
			}
		}
		r.matchTo = nil
		if r.Match != nil && r.Match.To != "" {
			re, err := regexp.Compile(r.Match.To)
			if err != nil {
				fail("routes.%s: match.to: %v", label, err)
			} else {
				r.matchTo = re
			}
		}
		if r.Transform != nil && r.Transform.To != "" && r.matchTo == nil {
			fail("routes.%s: transform.to requires match.to (capture groups come from it)", label)
		}
	}

	if _, err := ParseRateLimit(c.Shield.RateLimit); err != nil {
		fail("shield.rate_limit: %v", err)
	}
	switch c.Shield.NFTables {
	case "auto", "on", "off":
	default:
		fail("shield.nftables: must be auto, on, or off, got %q", c.Shield.NFTables)
	}

	if c.Admin != nil {
		if _, err := netip.ParseAddrPort(c.Admin.Listen); err != nil {
			fail("admin.listen: %q is not host:port", c.Admin.Listen)
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// parsePrefixOrAddr accepts "10.0.0.0/8" or a bare "203.0.113.7"
// (treated as a single-host prefix).
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is neither a CIDR nor an IP", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./config/ -v`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ && git commit -m "feat(config): cross-reference validation with aggregated errors"
```

---

### Task 4: Loader — file read, env expansion, strict parse with line numbers

**Files:**
- Create: `config/loader.go`
- Test: `config/loader_test.go`

**Interfaces:**
- Consumes: `Config`, `withDefaults`, `Validate` from Tasks 2–3.
- Produces:
  - `func Load(path string) (*Config, error)` — read + Parse. Task 6 (reload) and Task 7 (main) call this.
  - `func Parse(data []byte) (*Config, error)` — expand `${VAR}`, strict-unmarshal (unknown keys rejected with line numbers via `yaml.FormatError`), apply defaults, validate.

- [ ] **Step 1: Write the failing test**

Create `config/loader_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalYAML = `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: pbx
    to: [pbx]
`

func TestParseMinimal(t *testing.T) {
	c, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Peers["pbx"].Transport != "udp" {
		t.Error("defaults not applied")
	}
	if c.Shield.NFTables != "auto" {
		t.Error("shield defaults not applied")
	}
}

func TestParseUnknownFieldRejectedWithLine(t *testing.T) {
	src := minimalYAML + "bogus_key: true\n"
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("expected unknown-field error")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Errorf("error should name the unknown key: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "line") && !strings.Contains(err.Error(), "12") {
		t.Errorf("error should carry position info: %q", err.Error())
	}
}

func TestParseEnvExpansion(t *testing.T) {
	t.Setenv("TEST_SBC_PASS", "s3cret")
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${TEST_SBC_PASS}\" }", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c.Peers["pbx"].Auth.Password; got != "s3cret" {
		t.Errorf("password = %q, want expanded env value", got)
	}
}

func TestParseMissingEnvVarFails(t *testing.T) {
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${TEST_SBC_UNSET_VAR}\" }", 1)
	_, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "TEST_SBC_UNSET_VAR") {
		t.Errorf("expected missing-env error naming the variable, got: %v", err)
	}
}

func TestParseInvalidConfigFails(t *testing.T) {
	src := strings.Replace(minimalYAML, "from: pbx", "from: ghost", 1)
	_, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run 'TestParse|TestLoad' -v`
Expected: FAIL (compile error: `Parse`, `Load` undefined).

- [ ] **Step 3: Write the implementation**

Create `config/loader.go`:

```go
package config

import (
	"fmt"
	"os"
	"regexp"

	"github.com/goccy/go-yaml"
)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse expands ${ENV_VAR} references, strictly unmarshals the YAML
// (unknown keys are errors, reported with line numbers), applies defaults,
// and validates. Secrets are expanded into memory only — callers must never
// write the expanded form back to disk.
func Parse(data []byte) (*Config, error) {
	expanded, err := expandEnv(data)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalWithOptions(expanded, &c, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("parse config:\n%s", yaml.FormatError(err, false, true))
	}
	withDefaults(&c)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config:\n%w", err)
	}
	return &c, nil
}

// expandEnv replaces every ${VAR} with the environment value; any reference
// to an unset variable is an error (silent empty strings hide typos).
func expandEnv(data []byte) ([]byte, error) {
	var missing []string
	out := envRef.ReplaceAllFunc(data, func(m []byte) []byte {
		name := string(envRef.FindSubmatch(m)[1])
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return m
		}
		return []byte(v)
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("undefined environment variable(s) referenced in config: %v", missing)
	}
	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./config/ -v`
Expected: PASS. If `TestParseUnknownFieldRejectedWithLine` fails on the position-info assertion, print the actual error text, adjust the assertion to whatever position marker goccy emits (it renders the offending source line with `>` and line numbers) — the requirement is that a human can locate the bad key, not an exact format.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ && git commit -m "feat(config): loader with strict YAML parsing, line-numbered errors, env expansion"
```

---

### Task 5: Atomic config store

**Files:**
- Create: `config/store.go`
- Test: `config/store_test.go`

**Interfaces:**
- Consumes: `Config` from Task 2.
- Produces (every future module reads config through this):
  - `func NewStore(c *Config) *Store`
  - `func (s *Store) Current() *Config` — lock-free snapshot; callers bind one snapshot per call/request and never see a torn config.
  - `func (s *Store) Replace(c *Config)`

- [ ] **Step 1: Write the failing test**

Create `config/store_test.go`:

```go
package config

import (
	"sync"
	"testing"
)

func TestStoreCurrentAndReplace(t *testing.T) {
	c1 := validConfig()
	s := NewStore(c1)
	if s.Current() != c1 {
		t.Fatal("Current should return the initial config")
	}
	c2 := validConfig()
	s.Replace(c2)
	if s.Current() != c2 {
		t.Fatal("Current should return the replaced config")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore(validConfig())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				s.Replace(validConfig())
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if s.Current() == nil {
					t.Error("Current returned nil")
					return
				}
			}
		}()
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run TestStore -v`
Expected: FAIL (compile error: `NewStore` undefined).

- [ ] **Step 3: Write the implementation**

Create `config/store.go`:

```go
package config

import "sync/atomic"

// Store publishes immutable *Config snapshots. Readers call Current and use
// that snapshot for the lifetime of one call/request; the hot-reload path
// calls Replace. Both are lock-free.
type Store struct {
	p atomic.Pointer[Config]
}

func NewStore(c *Config) *Store {
	s := &Store{}
	s.p.Store(c)
	return s
}

// Current returns the active config snapshot. Never nil.
func (s *Store) Current() *Config { return s.p.Load() }

// Replace atomically swaps in a new validated config. In-flight calls keep
// the snapshot they already hold.
func (s *Store) Replace(c *Config) { s.p.Store(c) }
```

- [ ] **Step 4: Run tests to verify they pass (with the race detector)**

Run: `go test ./config/ -run TestStore -race -v`
Expected: PASS, no race reports.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ && git commit -m "feat(config): lock-free atomic config store"
```

---

### Task 6: Hot reload watcher

**Files:**
- Create: `config/reload.go`
- Test: `config/reload_test.go`

**Interfaces:**
- Consumes: `Load` (Task 4), `Store` (Task 5).
- Produces: `func Watch(ctx context.Context, path string, store *Store, log *slog.Logger) error` — blocks until ctx cancel; on file change: Load → success ⇒ `store.Replace` + info log; failure ⇒ error log, old config stays (spec §7). Task 7's main starts this in a goroutine.

- [ ] **Step 1: Write the failing test**

Create `config/reload_test.go`:

```go
package config

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func startWatch(t *testing.T, path string, store *Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	go func() { _ = Watch(ctx, path, store, log) }()
	time.Sleep(100 * time.Millisecond) // let the watcher attach
}

func TestWatchReloadsValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	updated := strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.99:5060", 1)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.99:5060"
	})
}

func TestWatchKeepsOldConfigOnBadReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	if err := os.WriteFile(path, []byte("listen: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	// Give the watcher time to (wrongly) swap; then assert it did not.
	time.Sleep(600 * time.Millisecond)
	if store.Current() != initial {
		t.Fatal("bad config must not replace the running config")
	}

	// And a subsequent good write still lands.
	updated := strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.42:5060", 1)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.42:5060"
	})
}

func TestWatchSurvivesAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	// Editors and `mv` replace the file via rename; the watcher must survive.
	tmp := filepath.Join(dir, ".sbc.yaml.tmp")
	updated := strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.77:5060", 1)
	if err := os.WriteFile(tmp, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.77:5060"
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run TestWatch -v`
Expected: FAIL (compile error: `Watch` undefined).

- [ ] **Step 3: Write the implementation**

Create `config/reload.go`:

```go
package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// reloadDebounce coalesces editor write bursts into one reload.
const reloadDebounce = 200 * time.Millisecond

// Watch monitors the config file and hot-swaps validated configs into store.
// It watches the parent directory (not the file) so atomic-rename saves keep
// working. An invalid config is logged and the previous one stays active —
// the process never dies from a bad reload. Blocks until ctx is cancelled.
func Watch(ctx context.Context, path string, store *Store, log *slog.Logger) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	if err := w.Add(filepath.Dir(abs)); err != nil {
		return err
	}

	base := filepath.Base(abs)
	fire := make(chan struct{}, 1)
	var timer *time.Timer
	schedule := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(reloadDebounce, func() {
			select {
			case fire <- struct{}{}:
			default:
			}
		})
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if filepath.Base(ev.Name) != base {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			schedule()
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			log.Error("config watcher error", "err", err)
		case <-fire:
			cfg, err := Load(abs)
			if err != nil {
				log.Error("config reload failed, keeping previous config", "err", err)
				continue
			}
			store.Replace(cfg)
			log.Info("config reloaded", "path", abs)
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass (race detector on)**

Run: `go test ./config/ -race -v`
Expected: PASS (all config tests, no races).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ && git commit -m "feat(config): fsnotify hot reload with validate-then-swap semantics"
```

---

### Task 7: CLI entrypoint + example config + end-to-end smoke

**Files:**
- Create: `main.go`
- Create: `sbc.example.yaml`
- Create: `.gitignore`

**Interfaces:**
- Consumes: `config.Load`, `config.NewStore`, `config.Watch` from Tasks 4–6.
- Produces: the `freesbc` binary with `run -c <file>` (start + hot reload + signal-clean shutdown) and `check -c <file>` (validate and exit). M2+ plans extend `run()` in `main.go`.

- [ ] **Step 1: Write the example config**

Create `sbc.example.yaml` (mirrors spec §5; copy it to `sbc.yaml` and edit to use):

```yaml
# FreeSBC example configuration.
# Copy to sbc.yaml, adjust, then:  freesbc run -c sbc.yaml

listen:
  sip:
    - udp://0.0.0.0:5060
    - tls://0.0.0.0:5061          # cert auto-generated (self-signed) if not configured
  media:
    port_range: 16384-32768
    public_ip: auto                # auto = STUN probe, or set a literal IP

peers:
  carrier-a:
    address: sip.carrier-a.com:5060   # DNS SRV honored, falls back to A/AAAA
    transport: udp
    auth: { username: acct01, password: "${CARRIER_A_PASS}" }
    register: true                 # registration-based trunk: periodic REGISTER
    allowed_ips: [203.0.113.0/24]  # inbound calls matched to this peer by source IP
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]

routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a]                # list order = failover order
  - name: inbound
    from: carrier-a
    to: [internal-pbx]

shield:                            # sensible defaults; the whole section is optional
  rate_limit: 20/s per_ip
  auto_ban: { failures: 5, window: 60s, duration: 1h }
  nftables: auto

admin:
  listen: 127.0.0.1:8080
  auth: { username: admin, password_hash: "$2a$10$replace-me" }
```

Create `.gitignore`:

```
/freesbc
/sbc.yaml
```

- [ ] **Step 2: Write main.go**

Create `main.go`:

```go
// Command freesbc is an all-in-one session border controller:
// one binary, one YAML file, `freesbc run`.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/freesbc/freesbc/config"
)

const usage = `FreeSBC — all-in-one session border controller

Usage:
  freesbc run   [-c sbc.yaml]   start the SBC
  freesbc check [-c sbc.yaml]   validate a config file and exit
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("c", "sbc.yaml", "path to config file")
	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "check":
		if _, err := config.Load(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "config invalid:\n%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s: config OK\n", *cfgPath)
	case "run":
		if err := run(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "freesbc: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func run(cfgPath string) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	store := config.NewStore(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := config.Watch(ctx, cfgPath, store, log); err != nil && ctx.Err() == nil {
			log.Error("config watcher exited", "err", err)
		}
	}()

	log.Info("freesbc started",
		"config", cfgPath,
		"peers", len(store.Current().Peers),
		"routes", len(store.Current().Routes))

	// M2+: media port pool, SIP listeners, shield, and admin API start here,
	// each reading snapshots via store.Current().

	<-ctx.Done()
	log.Info("shutting down")
	return nil
}
```

- [ ] **Step 3: Build and smoke-test the CLI end to end**

```bash
go build -o freesbc . && CARRIER_A_PASS=test ./freesbc check -c sbc.example.yaml
```

Expected output: `sbc.example.yaml: config OK`

```bash
./freesbc check -c sbc.example.yaml
```

Expected: exit 1, stderr names `CARRIER_A_PASS` as an undefined environment variable.

```bash
printf 'bogus: config' > /tmp/bad.yaml; ./freesbc check -c /tmp/bad.yaml; echo "exit=$?"
```

Expected: `exit=1` and an error mentioning `bogus`.

```bash
CARRIER_A_PASS=test ./freesbc run -c sbc.example.yaml & PID=$!
sleep 1; kill -TERM $PID; wait $PID; echo "exit=$?"
```

Expected: startup log line (`freesbc started ... peers=2 routes=2`), then `shutting down`, `exit=0`.

- [ ] **Step 4: Run the full test suite one last time**

Run: `go vet ./... && go test ./... -race`
Expected: vet clean, all tests PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add main.go sbc.example.yaml .gitignore && git commit -m "feat: freesbc CLI with run/check commands and example config"
```

---

## Spec Coverage (M1 slice)

| Spec requirement | Task |
|---|---|
| §2/§5 declarative YAML single source of truth | 2, 4 |
| §5 config file shape (listen/peers/routes/shield/admin) | 2 |
| §5 `${ENV_VAR}` expansion, never written back expanded | 4 (runtime-only expansion; AST write-back lands in M7 WebUI) |
| §3 decision 3: validate → atomic swap → snapshot per call | 4, 5, 6 |
| §7 bad config at startup: exit with line/field | 4, 7 |
| §7 bad config at reload: keep old, log | 6 |
| §4 deps: goccy/go-yaml + fsnotify only | 1 |
| Caddy-like UX: one binary, `run`/`check` | 7 |

Deferred to later milestones (intentionally, per roadmap): everything under `sig/`, `media/`, `shield/`, `admin/`, `callstate/`; STUN resolution of `public_ip: auto` (M2); TLS cert self-signing (M3); bcrypt verification of `admin.auth.password_hash` (M7).

## Post-Implementation Amendments (2026-07-15, final review)

The as-built code deviates from this plan in three reviewed-and-approved ways:
1. **Env expansion is post-parse, not byte-level** (`config/expand.go`): raw YAML is strict-parsed first (errors are secret-free and reference the user's real file), then `${VAR}` is expanded via a reflection walk over decoded string fields. Malformed refs (`${VAR:-default}`) are hard errors. Trade-off: `${VAR}` does not work inside compound scalars (port_range, durations, listener URLs).
2. **`Validate` is unexported** (`validate`); `Parse` is the only public entry point, preserving the immutable-snapshot contract.
3. **`auto_ban` bounds are validated** (failures ≥ 1, window/duration > 0).

## Carry-over Backlog for M2 (from final review)

- **Important:** quoted custom scalars break parsing — `port_range: "16384-32768"`, `window: "60s"`, `sip: ["udp://..."]` all fail because `UnmarshalYAML([]byte)` receives the raw node including quotes (`config/types.go`). Fix by decoding the node to a string first; a two-phase decode would also re-enable `${VAR}` in compound scalars. First config task of M2.
- Cosmetic: doubled error prefix `config invalid:` + `invalid config:` (main.go + Parse wrap).
- Minor deferred items: Shield YAML round-trip assertions; `NewStore` nil-arg doc; reload negative-assertion test uses fixed 600ms sleep; top-level `-h` exits 2; watcher goroutine needs coordinated shutdown once `run()` owns listeners.
