package media

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
