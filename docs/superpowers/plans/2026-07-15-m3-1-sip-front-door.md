# FreeSBC M3.1 — SIP Front Door Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `sig` package that assembles a sipgo SIP server on the configured listeners (UDP/TCP/TLS), identifies inbound requests by transport source IP, answers OPTIONS health checks from known peers, and silently drops requests from unknown sources — the "front door" before the B2BUA bridge (M3.3) exists.

**Architecture:** `sig.Server` holds the config store and a logger. `Run(ctx)` builds a sipgo `UserAgent`/`Server`, binds one listener per `listen.sip` entry (TLS listeners get an in-memory self-signed cert since no cert config exists yet), registers handlers, and blocks until ctx cancel. Every inbound request is matched against `peers[].allowed_ips` by its **transport** source address (sipgo sets `req.Source()` from the real remote on receive — the sender cannot spoof it); unknown sources are dropped (the seam where M6's shield plugs in). OPTIONS from a known peer → 200 OK. INVITE from a known peer → 100 Trying + a temporary 501 stub that M3.3 replaces with the bridge. Handlers read a fresh `store.Current()` snapshot per request, so hot-reloaded peer lists apply immediately.

**Tech Stack:** `github.com/emiago/sipgo` (SIP stack) + its `sip` subpackage; Go stdlib (`crypto/tls`, `crypto/x509`, `crypto/ecdsa`, `net`, `net/netip`). Integration tests use raw UDP SIP text (no dependency on sipgo's client API).

**Roadmap context:** First of three M3 slices (M3.1 front door → M3.2 routing → M3.3 bridge). The end-to-end call only lights up at the end of M3.3. Deferred from M3.1: routing (M3.2); B2BUA leg pairing, SDP rewrite, media wiring, `Relatch` (M3.3); digest auth, outbound REGISTER, session timers, PRACK, DNS SRV (M4); real shield logic (M6 — M3.1 leaves the drop seam); configurable TLS certs and STUN `public_ip: auto` (later).

## Global Constraints

- Module `github.com/freesbc/freesbc`, Go ≥ 1.22. Dependencies now include `github.com/emiago/sipgo` (approved in spec §4). Still no database, no Redis, no web framework.
- All code, comments, and log messages in English. Tests use stdlib `testing` only (no assertion libraries).
- Every task: `gofmt -l .` prints nothing before committing; the final task runs `go vet ./... && go test ./... -race`.
- Config lifecycle contract (M1): read snapshots via `(*config.Store).Current()`; snapshots are immutable; never mutate a `*config.Config` after publishing.
- **Security boundary:** inbound peer identification uses the transport source address from `req.Source()` (sipgo sets it from the real remote socket on receive). Never trust the Via/From/Contact host for identification.
- Spec §3 (topology hiding via B2BUA) and the interop baseline: OPTIONS answering lands here; session timers/PRACK are M4.
- Spec §6 step 2–3: unknown source → shield (default silent drop); known source → identify peer by `allowed_ips`.
- Deviation note: the spec §4 sketch names `sig/server.go`, `sig/routing.go`, etc. M3.1 creates only `sig/server.go`, `sig/identify.go`, `sig/tlscert.go`; the rest arrive in later M3 slices.
- Integration tests bind fixed localhost UDP ports in the 45060–45090 range; shift if a CI machine collides.
- sipgo API surface this plan targets (verify against the resolved version in Task 3; STOP and report if materially different): `sipgo.NewUA() (*UserAgent, error)`, `sipgo.NewServer(ua) (*Server, error)`, `srv.OnRequest(sip.OPTIONS, h)`, `srv.OnInvite(h)`, `srv.OnAck(h)`, handler `func(req *sip.Request, tx sip.ServerTransaction)`, `sip.NewResponseFromRequest(req, code int, reason string, body []byte) *sip.Response`, `tx.Respond(res) error`, `req.Source() string` ("host:port"), `srv.ListenAndServe(ctx, network, addr) error`, `srv.ListenAndServeTLS(ctx, network, addr, *tls.Config) error`, `ua.Close()`.

---

### Task 1: Peer identification by source IP

**Files:**
- Create: `sig/identify.go`
- Test: `sig/identify_test.go`

**Interfaces:**
- Consumes: `config.Config`, `config.Peer`, `(*config.Peer).AllowsIP(netip.Addr) bool` (M1). Note `AllowsIP` only works after `Validate`/`Parse` has compiled `allowedNets`, which is always true for a published snapshot.
- Produces (Tasks 3+ rely on this): `func IdentifyPeer(cfg *config.Config, addr netip.Addr) (name string, peer *config.Peer, ok bool)` — returns the first peer (by sorted name, for determinism) whose `allowed_ips` contains `addr`.

- [ ] **Step 1: Write the failing test**

Create `sig/identify_test.go`:

```go
package sig

import (
	"net/netip"
	"testing"

	"github.com/freesbc/freesbc/config"
)

func TestIdentifyPeer(t *testing.T) {
	src := `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    auth: { username: u, password: p }
    allowed_ips: [203.0.113.0/24]
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: carrier-a
    to: [internal-pbx]
`
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	name, peer, ok := IdentifyPeer(cfg, netip.MustParseAddr("203.0.113.7"))
	if !ok || name != "carrier-a" || peer == nil {
		t.Errorf("203.0.113.7 → %q, ok=%v", name, ok)
	}
	name, _, ok = IdentifyPeer(cfg, netip.MustParseAddr("10.1.2.3"))
	if !ok || name != "internal-pbx" {
		t.Errorf("10.1.2.3 → %q, ok=%v", name, ok)
	}
	if _, _, ok := IdentifyPeer(cfg, netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("192.0.2.1 should not match any peer")
	}
}

func TestIdentifyPeerDeterministicOnOverlap(t *testing.T) {
	// Two peers whose ranges both contain the address; the sorted-name
	// winner must be stable across runs (map iteration is not).
	src := `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  aaa:
    address: 10.0.0.1:5060
    allowed_ips: [10.0.0.0/8]
  zzz:
    address: 10.0.0.2:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: aaa
    to: [zzz]
`
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := 0; i < 20; i++ {
		name, _, ok := IdentifyPeer(cfg, netip.MustParseAddr("10.9.9.9"))
		if !ok || name != "aaa" {
			t.Fatalf("iteration %d: got %q (want deterministic \"aaa\")", i, name)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -v`
Expected: FAIL (package doesn't compile — `IdentifyPeer` undefined).

- [ ] **Step 3: Implement**

Create `sig/identify.go`:

```go
// Package sig implements the SIP signaling plane: the sipgo server
// assembly, inbound peer identification, and (in later M3 slices) the
// B2BUA bridge, routing, and SDP rewrite.
package sig

import (
	"net/netip"
	"sort"

	"github.com/freesbc/freesbc/config"
)

// IdentifyPeer returns the peer whose allowed_ips contains addr. When more
// than one peer matches, the lexicographically-first name wins, so the
// result is deterministic regardless of map iteration order. ok is false
// when no peer matches (the caller hands such requests to the shield seam).
func IdentifyPeer(cfg *config.Config, addr netip.Addr) (name string, peer *config.Peer, ok bool) {
	names := make([]string, 0, len(cfg.Peers))
	for n := range cfg.Peers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := cfg.Peers[n]
		if p.AllowsIP(addr) {
			return n, p, true
		}
	}
	return "", nil, false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./sig/ -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): identify inbound peer by transport source IP"
```

---

### Task 2: Self-signed TLS config

**Files:**
- Create: `sig/tlscert.go`
- Test: `sig/tlscert_test.go`

**Interfaces:**
- Consumes: nothing project-local.
- Produces (Task 3 relies on this): `func selfSignedTLSConfig() (*tls.Config, error)` — a `*tls.Config` with one freshly-generated in-memory self-signed ECDSA certificate. Package-private; the design's "cert not configured → self-signed" (spec §5) with no persisted key.

- [ ] **Step 1: Write the failing test**

Create `sig/tlscert_test.go`:

```go
package sig

import (
	"crypto/tls"
	"testing"
)

func TestSelfSignedTLSConfig(t *testing.T) {
	conf, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("selfSignedTLSConfig: %v", err)
	}
	if len(conf.Certificates) != 1 {
		t.Fatalf("want exactly 1 certificate, got %d", len(conf.Certificates))
	}
	// The certificate must be usable: a TLS server handshake path parses
	// the leaf, so a nil leaf or empty chain would be a broken config.
	if len(conf.Certificates[0].Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
	if conf.Certificates[0].PrivateKey == nil {
		t.Fatal("certificate has no private key")
	}
	// Two calls must produce independent certs (no shared global state).
	conf2, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if string(conf.Certificates[0].Certificate[0]) == string(conf2.Certificates[0].Certificate[0]) {
		t.Error("two calls produced identical certificates")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestSelfSignedTLSConfig -v`
Expected: FAIL (compile error: `selfSignedTLSConfig` undefined).

- [ ] **Step 3: Implement**

Create `sig/tlscert.go`:

```go
package sig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// selfSignedTLSConfig builds a TLS config backed by a freshly generated,
// in-memory, self-signed ECDSA certificate. FreeSBC has no per-listener
// certificate configuration yet, so TLS listeners self-sign (spec §5:
// "cert not configured → self-signed"). The key is never persisted; each
// process start (and each call) mints a new certificate.
func selfSignedTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "FreeSBC self-signed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("assemble keypair: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
```

Note: `time.Now()` is available here (this is production code, not a workflow script). The two-calls-differ test relies on distinct random serials/keys.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./sig/ -run TestSelfSignedTLSConfig -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): in-memory self-signed TLS config for TLS listeners"
```

---

### Task 3: Server assembly, handlers, lifecycle

**Files:**
- Create: `sig/server.go`
- Test: `sig/server_test.go`

**Interfaces:**
- Consumes: `IdentifyPeer` (Task 1), `selfSignedTLSConfig` (Task 2), `config.Store`, `config.SIPListen`; sipgo per the Global Constraints API list.
- Produces (Task 4 and M3.3 rely on these): `func NewServer(store *config.Store, log *slog.Logger) *Server`; `func (s *Server) Run(ctx context.Context) error` (binds all listeners, blocks until ctx done, returns the first fatal listener error or nil on clean shutdown). Package-private handler methods `onOptions`, `onInvite`, `onAck` and helper `identify(*sip.Request) (name string, peer *config.Peer, ok bool)`.

- [ ] **Step 1: Add the dependency**

```bash
cd /Users/rasonyang/workspaces/cc/freesbc
go get github.com/emiago/sipgo@latest
```

Record the resolved version from `go.mod` in your report. If it is older than v0.30 or the handler signatures below do not compile, STOP and report BLOCKED with the actual signatures — do not invent a different API.

- [ ] **Step 2: Write the failing test**

Create `sig/server_test.go`:

```go
package sig

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/config"
)

// startServer boots a sig.Server on the given UDP port with the given
// config YAML and returns once it is accepting packets. The server stops
// when the test ends.
func startServer(t *testing.T, port int, cfgYAML string) {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore(cfg)
	srv := NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx) }()
	// Wait until the UDP port answers (bind completed).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
			time.Sleep(100 * time.Millisecond)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not start")
}

// sipRequest builds a minimal valid SIP request whose Via advertises
// localAddr so the response returns to our socket.
func sipRequest(method, targetPort string, localAddr *net.UDPAddr, callID string) string {
	return strings.Join([]string{
		fmt.Sprintf("%s sip:sbc@127.0.0.1:%s SIP/2.0", method, targetPort),
		fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-%s", localAddr.String(), callID),
		"From: <sip:tester@127.0.0.1>;tag=t1",
		"To: <sip:sbc@127.0.0.1>",
		"Call-ID: " + callID,
		fmt.Sprintf("CSeq: 1 %s", method),
		"Contact: <sip:tester@" + localAddr.String() + ">",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
}

// roundTrip sends one request and collects response datagrams until it
// sees wantSubstr or the timeout elapses. Returns all received text.
func roundTrip(t *testing.T, targetPort int, method, callID string, timeout time.Duration, wantSubstr string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort}
	req := sipRequest(method, fmt.Sprintf("%d", targetPort), local, callID)
	if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		if wantSubstr != "" && strings.Contains(got.String(), wantSubstr) {
			return got.String()
		}
	}
	return got.String()
}

const knownPeerCfg = `
listen:
  sip: [udp://127.0.0.1:45060]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: in
    from: local-uac
    to: [local-uac]
`

func TestServerAnswersOptionsFromKnownPeer(t *testing.T) {
	startServer(t, 45060, knownPeerCfg)
	got := roundTrip(t, 45060, "OPTIONS", "opt-known-1", 3*time.Second, "SIP/2.0 200")
	if !strings.Contains(got, "SIP/2.0 200") {
		t.Fatalf("expected 200 OK to OPTIONS, got:\n%s", got)
	}
}

func TestServerInviteFromKnownPeerGetsStub(t *testing.T) {
	startServer(t, 45062, strings.Replace(knownPeerCfg, "45060", "45062", 1))
	got := roundTrip(t, 45062, "INVITE", "inv-known-1", 3*time.Second, "SIP/2.0 501")
	if !strings.Contains(got, "SIP/2.0 100") {
		t.Errorf("expected 100 Trying, got:\n%s", got)
	}
	if !strings.Contains(got, "SIP/2.0 501") {
		t.Errorf("expected 501 stub, got:\n%s", got)
	}
}

func TestServerDropsUnknownSource(t *testing.T) {
	// allowed_ips excludes loopback → our OPTIONS must be silently dropped.
	cfg := strings.Replace(
		strings.Replace(knownPeerCfg, "45060", "45064", 1),
		"127.0.0.1/32", "10.0.0.0/8", 1)
	startServer(t, 45064, cfg)
	got := roundTrip(t, 45064, "OPTIONS", "opt-unknown-1", 1*time.Second, "")
	if strings.Contains(got, "SIP/2.0") {
		t.Fatalf("unknown source must be dropped, but got a response:\n%s", got)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./sig/ -run TestServer -v`
Expected: FAIL (compile error: `NewServer` undefined).

- [ ] **Step 4: Implement**

Create `sig/server.go`:

```go
package sig

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/config"
)

// Server is the SIP signaling front door. It binds the configured
// listeners, identifies inbound requests by transport source IP, and
// answers OPTIONS health checks. The B2BUA bridge is wired in M3.3.
type Server struct {
	store *config.Store
	log   *slog.Logger
}

func NewServer(store *config.Store, log *slog.Logger) *Server {
	return &Server{store: store, log: log}
}

// Run builds the sipgo server, binds every listen.sip entry, and blocks
// until ctx is cancelled. It returns the first fatal listener error (e.g.
// a bind failure), or nil on clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	ua, err := sipgo.NewUA()
	if err != nil {
		return fmt.Errorf("sipgo ua: %w", err)
	}
	defer ua.Close()
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		return fmt.Errorf("sipgo server: %w", err)
	}
	srv.OnRequest(sip.OPTIONS, s.onOptions)
	srv.OnInvite(s.onInvite)
	srv.OnAck(s.onAck)

	listeners := s.store.Current().Listen.SIP
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for _, l := range listeners {
		l := l
		addr := net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lerr error
			switch l.Transport {
			case "tls":
				tlsConf, cerr := selfSignedTLSConfig()
				if cerr != nil {
					lerr = cerr
					break
				}
				s.log.Warn("TLS listener using self-signed certificate", "addr", addr)
				lerr = srv.ListenAndServeTLS(ctx, "tcp", addr, tlsConf)
			default:
				lerr = srv.ListenAndServe(ctx, l.Transport, addr)
			}
			if lerr != nil && ctx.Err() == nil {
				errs <- fmt.Errorf("listen %s://%s: %w", l.Transport, addr, lerr)
				cancel()
			}
		}()
	}
	s.log.Info("sip server listening", "listeners", len(listeners))

	<-ctx.Done()
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

// identify resolves the peer for an inbound request by its transport
// source address. sipgo sets req.Source() from the real remote socket on
// receive, so this is the trust boundary — never the Via/From host.
func (s *Server) identify(req *sip.Request) (string, *config.Peer, bool) {
	host, _, err := net.SplitHostPort(req.Source())
	if err != nil {
		return "", nil, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", nil, false
	}
	return IdentifyPeer(s.store.Current(), addr)
}

// dropUnidentified is the shield seam (M6): a request from a source that
// matches no peer is silently dropped (spec §6 step 2). No response is
// sent; the transaction ages out on its own.
func (s *Server) dropUnidentified(req *sip.Request) {
	s.log.Info("dropping request from unidentified source",
		"method", req.Method.String(), "source", req.Source())
}

func (s *Server) onOptions(req *sip.Request, tx sip.ServerTransaction) {
	name, _, ok := s.identify(req)
	if !ok {
		s.dropUnidentified(req)
		return
	}
	if err := tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil)); err != nil {
		s.log.Error("respond OPTIONS", "peer", name, "err", err)
	}
}

func (s *Server) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	name, _, ok := s.identify(req)
	if !ok {
		s.dropUnidentified(req)
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
	// M3.3 replaces this stub with the B2BUA bridge (routing → media
	// allocate → SDP rewrite → B-leg INVITE).
	if err := tx.Respond(sip.NewResponseFromRequest(req, 501, "Not Implemented", nil)); err != nil {
		s.log.Error("respond INVITE stub", "peer", name, "err", err)
	}
	s.log.Info("INVITE received (bridge not yet implemented)", "peer", name)
}

// onAck absorbs ACKs (e.g. the ACK to the 501 stub's final response) so
// sipgo does not log them as unhandled. Real in-dialog ACK handling is M3.3.
func (s *Server) onAck(req *sip.Request, tx sip.ServerTransaction) {}
```

- [ ] **Step 5: Run tests to verify they pass (race detector on)**

Run: `go test ./sig/ -race -v`
Expected: PASS (all sig tests). If the sipgo handler signatures differ from the plan, the compile error surfaces here — see Step 1's BLOCKED instruction.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && git add sig/ go.mod go.sum && git commit -m "feat(sig): sipgo front door — listeners, OPTIONS, source-IP identification"
```

---

### Task 4: Wire the SIP server into `run()` + docs + full verification

**Files:**
- Modify: `main.go`
- Modify: `README.md`

**Interfaces:**
- Consumes: `sig.NewServer(store, log)`, `(*sig.Server).Run(ctx)` (Task 3); `media.NewPool` (M2, already wired).
- Produces: `run()` starts the SIP server in the shutdown WaitGroup alongside the config watcher. M3.3 will pass the media pool into `NewServer`.

- [ ] **Step 1: Wire the server**

In `main.go`, add `"github.com/freesbc/freesbc/sig"` to the imports. In `run()`, immediately after the `media plane ready` log block and before the `freesbc started` log, replace the `// M3+: SIP listeners, ...` comment with:

```go
	sipServer := sig.NewServer(store, log)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sipServer.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("sip server exited", "err", err)
			stop() // a fatal bind error tears the whole process down
		}
	}()

	// M3.3+: the B2BUA bridge, shield, and admin API attach here.
```

(`stop` is the `signal.NotifyContext` cancel func already in scope; calling it unblocks `<-ctx.Done()` so a failed bind shuts the process down cleanly instead of running deaf.)

- [ ] **Step 2: Update the README roadmap**

In `README.md`, split the M3 row into the three M3 slices, marking M3.1 done:

```markdown
| M3 | Signaling core: SIP server, B2BUA, SDP rewrite, routing — first end-to-end call | in progress |
| ├ M3.1 | SIP front door: listeners, OPTIONS, source-IP identification | ✅ done |
| ├ M3.2 | Routing engine: match / transform / failover | next |
| └ M3.3 | B2BUA bridge: leg pairing, SDP rewrite, media wiring, Relatch | |
```

(Replace only the single existing M3 row with these four lines; leave M4–M7 unchanged.)

- [ ] **Step 3: Full verification + smoke test**

```bash
go vet ./... && go test ./... -race
```

Expected: vet clean; all config, media, and sig tests PASS.

```bash
go build -o freesbc . && CARRIER_A_PASS=test ./freesbc run -c sbc.example.yaml & PID=$!
sleep 1; kill -TERM $PID; wait $PID; echo "exit=$?"
```

Expected: startup logs include `media plane ready`, `sip server listening listeners=2`, and `freesbc started`; `sbc.example.yaml` binds `udp://0.0.0.0:5060` and `tls://0.0.0.0:5061` (the TLS listener logs the self-signed-certificate warning); then `shutting down`, `exit=0`.

If binding `:5060`/`:5061` requires privileges or the ports are busy on this machine, copy `sbc.example.yaml` to the scratchpad, change the listeners to `udp://127.0.0.1:45060` / `tls://127.0.0.1:45061`, and run against that copy — note the substitution in your report.

- [ ] **Step 4: Commit**

```bash
gofmt -l . && git add main.go README.md && git commit -m "feat: start SIP front door in run(); mark M3.1 done in roadmap"
```

---

## Spec Coverage (M3.1 slice)

| Spec requirement | Task |
|---|---|
| §4 `sig/server.go` — sipgo assembly (UDP/TCP/TLS) | 3 |
| §5 listen.sip multiple transports; self-signed cert when tls certificate is not configured | 2, 3 |
| §6 step 2–3 — identify peer by source IP; hand unmatched traffic to shield (silent drop) | 1, 3 |
| Interop baseline — answer inbound OPTIONS | 3 |
| §3 — sig reads a config.Current() snapshot (consistent per request) | 3 |
| Caddy-like — start the SIP service inside a single process | 4 |

Deferred to later M3 slices and milestones (documented in header): routing match/transform/failover (M3.2); B2BUA leg pairing, SDP rewrite, media `Allocate`/`SetExpectedRemote`/`Relatch` wiring, in-dialog ACK/BYE (M3.3); digest auth, outbound REGISTER, session timers, PRACK, DNS SRV (M4); real shield verdicts replacing `dropUnidentified` (M6); configurable TLS certificates and STUN `public_ip: auto` (later).
