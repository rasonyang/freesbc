package media

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
)

// Regression tests for audit findings that had no test in the audit
// itself. They draw ports from 24700-24999, which the audit suites leave
// free.

// audit: P2-MED-012
//
// Start must be a one-shot transition out of legAllocated. A second Start
// used to launch a second establish over the same socket, whose ICE agent
// replaced the first in l.agent and was never closed; a Start after Close
// launched an establish nobody would ever tear down.
func TestAuditMED012StartIsOneShot(t *testing.T) {
	pool := newAuditPool("public", 24700, 24739, "127.0.0.1")
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
		RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
	}
	// Warm up pion's package-level state so it is not counted as a leak.
	if warm, err := NewWebRTCLeg(pool.PlanePool, cfg); err == nil {
		warm.Start(context.Background(), 50*time.Millisecond)
		<-warm.Ready()
	}
	baseline, _ := auditWaitGoroutines(0, 0, 500*time.Millisecond)

	const establishTimeout = 200 * time.Millisecond
	t.Run("TwiceThenClose", func(t *testing.T) {
		leg, err := NewWebRTCLeg(pool.PlanePool, cfg)
		if err != nil {
			t.Fatal(err)
		}
		leg.Start(context.Background(), time.Hour)
		leg.Start(context.Background(), time.Hour)
		time.Sleep(50 * time.Millisecond) // let both establishes build an agent
		_ = leg.Close()
		<-leg.Ready()
	})
	t.Run("AfterClose", func(t *testing.T) {
		leg, err := NewWebRTCLeg(pool.PlanePool, cfg)
		if err != nil {
			t.Fatal(err)
		}
		_ = leg.Close()
		leg.Start(context.Background(), establishTimeout)
		<-leg.Ready()
		if leg.Err() == nil {
			t.Error("a leg started after Close reported success")
		}
	})
	time.Sleep(establishTimeout + 100*time.Millisecond)
	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("pool in use after closing every leg: %d, want 0", inUse)
	}
	if got, ok := auditWaitGoroutines(baseline, 2, 5*time.Second); !ok {
		t.Errorf("P2-MED-012: goroutines did not return to baseline: baseline=%d now=%d; stacks %v",
			baseline, got, auditGoroutineSummary("pion/ice", "pion/transport", "media.(*WebRTCLeg)"))
	}
}

// audit: P2-MED-002
//
// With the signalled fingerprint in its config, the leg checks it inside
// the DTLS handshake: a peer presenting another certificate never gets a
// leg in legEstablished, no SRTP keys, and no relay. Before the fix the
// handshake accepted any certificate and the check ran only afterwards.
func TestAuditMED002HandshakeRejectsMismatchedFingerprint(t *testing.T) {
	pub := newAuditPool("public", 24740, 24779, "127.0.0.1")
	priv := newAuditPool("private", 24780, 24819, "127.0.0.1")
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	browserCert, err := selfSignedForTest()
	if err != nil {
		t.Fatal(err)
	}
	signalled, err := selfSignedForTest() // what the offer claimed
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	browser, bUfrag, bPwd := auditBrowserAgent(t)
	leg, err := NewWebRTCLeg(pub.PlanePool, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"),
		RemoteUfrag:  bUfrag, RemotePwd: bPwd,
		RemoteSetup: "actpass", Identity: id,
		RemoteFingerprintHash:  "sha-256",
		RemoteFingerprintValue: fingerprintOf(signalled),
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewWebRTCSession(leg, priv.PlanePool, WebRTCSessionConfig{PrivateLatch: LatchStrict, Timeout: time.Hour})
	if err != nil {
		_ = leg.Close()
		t.Fatal(err)
	}
	defer sess.Close()
	leg.Start(context.Background(), 15*time.Second)
	bDemux := auditBrowserICE(ctx, t, browser, leg)
	bDTLS, err := dtls.ClientWithOptions(bDemux.dtls, bDemux.dtls.RemoteAddr(),
		dtls.WithCertificates(browserCert),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithInsecureSkipVerify(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bDTLS.Close()
	go func() { _ = bDTLS.HandshakeContext(ctx) }()

	if err := sess.Start(ctx); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("session start with a mismatched DTLS peer = %v, want ErrFingerprintMismatch", err)
	}
	if !errors.Is(leg.Err(), ErrFingerprintMismatch) {
		t.Errorf("leg error = %v, want ErrFingerprintMismatch", leg.Err())
	}
	if _, _, err := leg.SRTPContexts(); err == nil {
		t.Error("a leg whose peer failed the fingerprint check has SRTP contexts")
	}
	for _, p := range []*auditPool{pub, priv} {
		if inUse, _ := p.Stats(); inUse != 0 {
			t.Errorf("pool %s: %d in use after the rejected handshake, want 0", p.name, inUse)
		}
	}
}

// audit: P2-MED-002
//
// A leg built without a signalled fingerprint establishes but carries no
// media until VerifyFingerprint succeeds; after that, audio flows.
func TestAuditMED002MediaFlowsOnlyAfterVerify(t *testing.T) {
	c := auditEstablishBrowserCall(t, 24820, 24859, 24860, 24899)
	// FreeSWITCH speaks first, so the private side is latched and the
	// only thing left to stop browser audio is the fingerprint gate.
	priv := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.sess.PrivateRTPPort()}
	if _, err := c.fsConn.WriteToUDP(rtpPacket(0, 100, 160), priv); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	send := func(seq uint16) bool {
		pkt := rtpPacket(0, seq, 160)
		prot, ok := c.browserOut.protectRTP(pkt)
		if !ok {
			t.Fatal("browser could not protect its RTP")
		}
		if _, err := c.bDemux.srtp.Write(prot); err != nil {
			t.Fatal(err)
		}
		_ = c.fsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 2000)
		n, _, err := c.fsConn.ReadFromUDP(buf)
		return err == nil && string(buf[:n]) == string(pkt)
	}
	if send(1) {
		t.Fatal("media relayed before the fingerprint was verified")
	}
	if err := c.leg.VerifyFingerprint("sha-256", fingerprintOf(c.browserCert)); err != nil {
		t.Fatalf("VerifyFingerprint(real certificate) = %v", err)
	}
	if !send(2) {
		t.Error("media not relayed after the fingerprint was verified")
	}
}

// audit: P1-007
//
// staticcheck SA1019 flagged the WebRTC leg's use of pion constructors
// marked for removal. This keeps the package's non-test code on the
// options-based APIs without needing staticcheck in the test run.
func TestAuditP1007NoDeprecatedPionAPIs(t *testing.T) {
	deprecated := map[string]bool{
		"ice.NewAgent": true, "ice.AgentConfig": true,
		"dtls.Client": true, "dtls.Server": true, "dtls.Config": true,
		"dtls.Dial": true, "dtls.Listen": true, "dtls.NewListener": true, "dtls.Resume": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && deprecated[x.Name+"."+sel.Sel.Name] {
				t.Errorf("P1-007: %s uses deprecated pion API %s.%s", fset.Position(sel.Pos()), x.Name, sel.Sel.Name)
			}
			return true
		})
	}
}

// auditBrowserAgent builds the full-ICE agent standing in for a browser.
func auditBrowserAgent(tb testing.TB) (agent *ice.Agent, ufrag, pwd string) {
	tb.Helper()
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelError
	agent, err := ice.NewAgentWithOptions(
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost}),
		ice.WithIncludeLoopback(),
		ice.WithLoggerFactory(lf),
	)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = agent.Close() })
	ufrag, pwd, err = agent.GetLocalUserCredentials()
	if err != nil {
		tb.Fatal(err)
	}
	return agent, ufrag, pwd
}

// auditBrowserICE runs the browser side of ICE against leg and returns
// the demultiplexed connection the browser's DTLS and SRTP ride on.
func auditBrowserICE(ctx context.Context, tb testing.TB, browser *ice.Agent, leg *WebRTCLeg) *demux {
	tb.Helper()
	cand, err := ice.NewCandidateHost(&ice.CandidateHostConfig{
		Network: "udp", Address: "127.0.0.1", Port: leg.Port(), Component: 1,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if err := browser.AddRemoteCandidate(cand); err != nil {
		tb.Fatal(err)
	}
	if err := browser.OnCandidate(func(ice.Candidate) {}); err != nil {
		tb.Fatal(err)
	}
	if err := browser.GatherCandidates(); err != nil {
		tb.Fatal(err)
	}
	lUfrag, lPwd := leg.LocalCredentials()
	conn, err := browser.Dial(ctx, lUfrag, lPwd)
	if err != nil {
		tb.Fatalf("browser ICE dial: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	dm := newDemux(conn)
	tb.Cleanup(func() { _ = dm.Close() })
	return dm
}

// audit: P2-MED-005
//
// Relatch used to take only an IP and forget the destination, so after an
// authorised media-address change the side received nothing until it sent
// first — never, for a recvonly peer or an IVR waiting to hear audio. It
// now re-seeds the send-to address from the signalled c=/m=.
func TestAuditMED005RelatchKeepsSendingToNewAddress(t *testing.T) {
	// A loopback lab: the pool allows loopback destinations.
	pool := NewPlanePool("audit", func() PlaneParams {
		return PlaneParams{
			MinPort: 24900, MaxPort: 24919, BindIP: netip.MustParseAddr("127.0.0.1"),
			Timeout: 30 * time.Second, AllowLoopback: true,
		}
	})
	s, err := pool.Allocate(SessionConfig{Latch: [2]LatchMode{LatchStrict, LatchStrict}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := auditUDP(t, "127.0.0.1")
	oldB := auditUDP(t, "127.0.0.1")
	newB := auditUDP(t, "127.0.0.1") // recvonly: never sends
	s.SetRemote(SideA, auditAddrPort(a))
	s.SetRemote(SideB, auditAddrPort(oldB))
	s.Start()
	// The original B latches by sending, as a live peer does.
	pubB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideB)}
	if _, err := oldB.WriteToUDP([]byte("b-audio"), pubB); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// A re-INVITE (or a new answer) moves B's media to newB.
	s.Relatch(SideB, auditAddrPort(newB))

	pubA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideA)}
	buf := make([]byte, 1500)
	got := false
	for i := 0; i < 10 && !got; i++ {
		if _, err := a.WriteToUDP([]byte("a-audio"), pubA); err != nil {
			t.Fatal(err)
		}
		_ = newB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if n, _, err := newB.ReadFromUDP(buf); err == nil && string(buf[:n]) == "a-audio" {
			got = true
		}
	}
	if !got {
		t.Error("P2-MED-005: after Relatch to a new address, the side never receives media until it sends first")
	}
}

// audit: P2-MED-003
//
// The loopback policy is the pool's: a pool that does not allow loopback
// arms the source check from a loopback c= but never sends to it, and one
// that does (a loopback lab) seeds it as usual.
func TestAuditMED003LoopbackSeedFollowsPoolPolicy(t *testing.T) {
	for _, allow := range []bool{false, true} {
		l := &latch{mode: LatchStrict, allowLoopback: allow}
		l.seed(netip.MustParseAddrPort("127.0.0.1:4000"))
		if got := l.target() != nil; got != allow {
			t.Errorf("allowLoopback=%v: destination installed = %v", allow, got)
		}
		if !l.accept(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}) {
			t.Errorf("allowLoopback=%v: a packet from the signalled loopback source was not accepted", allow)
		}
	}
	// A public address is seeded either way.
	l := &latch{mode: LatchStrict}
	l.seed(netip.MustParseAddrPort("198.51.100.7:4000"))
	if l.target() == nil {
		t.Error("a unicast public address was not seeded")
	}
}

// audit: P1-012
//
// The Session relay read into a 1500-byte buffer while the WebRTC path
// uses maxPacketSize (1508), and ReadFromUDP silently truncates: a larger
// datagram was forwarded cut short. Now every relay reads up to
// maxPacketSize and drops anything larger rather than forward a
// truncation.
func TestAuditP1012RelayBufferMatchesMaxPacketSize(t *testing.T) {
	pool := NewPlanePool("audit", func() PlaneParams {
		return PlaneParams{
			MinPort: 24920, MaxPort: 24939, BindIP: netip.MustParseAddr("127.0.0.1"),
			Timeout: 30 * time.Second, AllowLoopback: true,
		}
	})
	s, err := pool.Allocate(SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchLoose}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := auditUDP(t, "127.0.0.1")
	b := auditUDP(t, "127.0.0.1")
	s.SetRemote(SideB, auditAddrPort(b))
	s.Start()
	pubA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideA)}
	buf := make([]byte, 4096)
	relay := func(size int) (int, bool) {
		pkt := make([]byte, size)
		for i := range pkt {
			pkt[i] = byte(i)
		}
		if _, err := a.WriteToUDP(pkt, pubA); err != nil {
			t.Fatal(err)
		}
		_ = b.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := b.ReadFromUDP(buf)
		if err != nil {
			return 0, false
		}
		return n, string(buf[:n]) == string(pkt[:n])
	}
	if n, ok := relay(maxPacketSize); !ok || n != maxPacketSize {
		t.Errorf("P1-012: a %d-byte datagram arrived as %d bytes (intact prefix %v)", maxPacketSize, n, ok)
	}
	if n, ok := relay(maxPacketSize + 200); ok {
		t.Errorf("P1-012: an oversize %d-byte datagram was forwarded as %d bytes; it must be dropped, not truncated", maxPacketSize+200, n)
	}
}

// audit: P2-MED-007
//
// The relays protect and unprotect in place in their own read buffers,
// which have room for the SRTP overhead: no allocation at all, not even
// the slab the generic API draws from.
func TestAuditMED007RelayPathInPlaceAllocatesNothing(t *testing.T) {
	key := NewSDESKey()
	send, _ := NewSRTPContext(SuiteAES128CM80, key)
	recv, _ := NewSRTPContext(SuiteAES128CM80, key)
	// Relay-style buffers: room for the SRTP overhead past the packet.
	// AllocsPerRun makes one extra warm-up call, hence runs+1.
	const runs = 1000
	pkts := make([][]byte, runs+1)
	for i := range pkts {
		p := make([]byte, 0, relayBufSize)
		pkts[i] = append(p, rtpPacket(0, uint16(i+1), 160)...)
	}
	// One transform per measured run, as TestAuditMED007SRTPAllocsPerPacket
	// does: under -race, sync.Pool (pion's XOR scratch) randomly drops
	// items, which shows up as a fraction of an allocation per call.
	i := 0
	protectAllocs := testing.AllocsPerRun(runs, func() {
		out, ok := send.protectRTPInto(pkts[i], pkts[i])
		if !ok {
			panic("protect")
		}
		pkts[i] = out
		i++
	})
	j := 0
	unprotectAllocs := testing.AllocsPerRun(runs, func() {
		if _, ok := recv.unprotectRTPInto(pkts[j], pkts[j]); !ok {
			panic("unprotect")
		}
		j++
	})
	if protectAllocs > 0 || unprotectAllocs > 0 {
		t.Errorf("P2-MED-007: the in-place relay path allocates per packet: protect=%.0f unprotect=%.0f", protectAllocs, unprotectAllocs)
	}
	if send.slab != nil || recv.slab != nil {
		t.Error("P2-MED-007: the in-place path drew on the slab")
	}
}

// audit: P2-MED-013
//
// Stats named side A "public" and side B "private", which is the edge
// proxy's orientation only: on the trunk B2BUA both legs face carriers or
// PBXs. The counters are now per side, with the orientation documented
// per plane.
func TestAuditMED013StatsAreSideNeutral(t *testing.T) {
	var names []string
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			names = append(names, f.Name)
			if f.Type.Kind() == reflect.Struct {
				walk(f.Type)
			}
		}
	}
	walk(reflect.TypeOf(Stats{}))
	for _, n := range names {
		if strings.Contains(n, "Public") || strings.Contains(n, "Private") {
			t.Errorf("P2-MED-013: Stats field %q names an edge-only orientation", n)
		}
	}
	var c counters
	c.recordRx(SideA, true, 100)
	c.recordTx(SideB, true, 40)
	st := c.snapshot()
	if st.Side(SideA).RTPBytesRx != 100 || st.Side(SideB).RTPBytesTx != 40 || st.Total().RTPPacketsRx != 1 {
		t.Errorf("P2-MED-013: counters not reported per side: %+v", st)
	}
}

// audit: P2-MED-010
//
// allocatePair held the pool mutex across the whole bind sweep, so one
// slow sweep (a range full of ports other processes hold) stalled every
// Stats, release and allocation on the plane. The mutex now covers only
// the reservation; the bind runs outside it.
func TestAuditMED010BindRunsOutsidePoolLock(t *testing.T) {
	pool := newAuditPool("audit", 24940, 24959, "127.0.0.1")
	entered := make(chan int, 1)
	unblock := make(chan struct{})
	orig := listenUDP
	var once sync.Once
	listenUDP = func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
		first := false
		once.Do(func() { first = true })
		if first {
			entered <- laddr.Port
			<-unblock
		}
		return orig(network, laddr)
	}
	defer func() { listenUDP = orig }()

	type res struct {
		pp  *portPair
		err error
	}
	slow := make(chan res, 1)
	go func() {
		pp, err := pool.allocatePair()
		slow <- res{pp, err}
	}()
	blockedPort := <-entered // the first allocation is now inside a bind

	statsDone := make(chan struct{})
	go func() {
		_, _ = pool.Stats()
		close(statsDone)
	}()
	fast := make(chan res, 1)
	go func() {
		pp, err := pool.allocatePair()
		fast <- res{pp, err}
	}()
	select {
	case <-statsDone:
	case <-time.After(2 * time.Second):
		t.Error("P2-MED-010: Stats blocked while another allocation was binding")
	}
	select {
	case r := <-fast:
		if r.err != nil {
			t.Errorf("concurrent allocation failed: %v", r.err)
		} else {
			if r.pp.RTPPort() == blockedPort {
				t.Errorf("concurrent allocation got the port still being bound (%d)", blockedPort)
			}
			r.pp.Close()
			pool.release(r.pp.RTPPort())
		}
	case <-time.After(2 * time.Second):
		t.Error("P2-MED-010: an allocation blocked while another was binding")
	}
	close(unblock)
	r := <-slow
	if r.err != nil {
		t.Fatalf("blocked allocation failed: %v", r.err)
	}
	r.pp.Close()
	pool.release(r.pp.RTPPort())
	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("pool in use after releasing both: %d", inUse)
	}
}
