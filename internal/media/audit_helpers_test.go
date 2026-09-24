package media

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
)

// Audit test port plan: every audit test in this package draws from
// 24000-24999, which no pre-existing suite in the repository uses.

// auditPool builds a loopback-bound pool whose range can be changed at
// runtime, standing in for a hot-reloaded listen.media.port_range.
type auditPool struct {
	*PlanePool
	lo, hi atomic.Int32
}

func newAuditPool(name string, lo, hi int, bind string) *auditPool {
	ap := &auditPool{}
	ap.lo.Store(int32(lo))
	ap.hi.Store(int32(hi))
	var ip netip.Addr
	if bind != "" {
		ip = netip.MustParseAddr(bind)
	}
	ap.PlanePool = NewPlanePool(name, func() PlaneParams {
		return PlaneParams{
			MinPort: uint16(ap.lo.Load()),
			MaxPort: uint16(ap.hi.Load()),
			BindIP:  ip,
			Timeout: 30 * time.Second,
		}
	})
	return ap
}

func (ap *auditPool) setRange(lo, hi int) {
	ap.lo.Store(int32(lo))
	ap.hi.Store(int32(hi))
}

// auditWaitGoroutines polls runtime.NumGoroutine until it is at most
// baseline+slack or the timeout expires (bounded retry, no goleak).
func auditWaitGoroutines(baseline, slack int, timeout time.Duration) (int, bool) {
	deadline := time.Now().Add(timeout)
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= baseline+slack {
			return n, true
		}
		if time.Now().After(deadline) {
			return n, false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// auditGoroutineSummary counts live goroutines whose stack mentions each
// of the given substrings, for failure messages.
func auditGoroutineSummary(subs ...string) map[string]int {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	out := map[string]int{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		for _, s := range subs {
			if strings.Contains(g, s) {
				out[s]++
			}
		}
	}
	return out
}

// auditUDP binds a UDP socket on ip:0, or skips when ip is not
// configured on this host (macOS has no 127.0.0.2 by default).
func auditUDP(tb testing.TB, ip string) *net.UDPConn {
	tb.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		tb.Skipf("cannot bind %s: %v", ip, err)
	}
	tb.Cleanup(func() { _ = c.Close() })
	return c
}

func auditAddrPort(c *net.UDPConn) netip.AddrPort {
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// auditBrowserCall is an established browser call at the media layer: a
// full-ICE "browser" has completed ICE and DTLS against a WebRTCLeg, and
// the WebRTCSession relay is running toward a fake FreeSWITCH socket.
type auditBrowserCall struct {
	leg         *WebRTCLeg
	sess        *WebRTCSession
	browserConn *ice.Conn
	bDemux      *demux
	browserOut  *SRTPContext
	browserIn   *SRTPContext
	browserCert tls.Certificate
	fsConn      *net.UDPConn
	pub, priv   *PlanePool
}

// auditEstablishBrowserCall builds an auditBrowserCall; it mirrors
// TestWebRTCSessionEndToEnd, and never calls VerifyFingerprint.
func auditEstablishBrowserCall(tb testing.TB, pubLo, pubHi, privLo, privHi int) *auditBrowserCall {
	tb.Helper()
	pub := newAuditPool("public", pubLo, pubHi, "127.0.0.1").PlanePool
	priv := newAuditPool("private", privLo, privHi, "127.0.0.1").PlanePool
	id, err := ProcessDTLSIdentity()
	if err != nil {
		tb.Fatal(err)
	}
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelError
	browser, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:    []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:  []ice.CandidateType{ice.CandidateTypeHost},
		IncludeLoopback: true,
		LoggerFactory:   lf,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = browser.Close() })
	bUfrag, bPwd, err := browser.GetLocalUserCredentials()
	if err != nil {
		tb.Fatal(err)
	}
	leg, err := NewWebRTCLeg(pub, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"),
		RemoteUfrag:  bUfrag, RemotePwd: bPwd,
		RemoteSetup: "actpass", Identity: id,
	})
	if err != nil {
		tb.Fatal(err)
	}
	sess, err := NewWebRTCSession(leg, priv, WebRTCSessionConfig{
		PrivateLatch: LatchStrict, Timeout: time.Hour,
	})
	if err != nil {
		_ = leg.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = sess.Close() })

	fsConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = fsConn.Close() })
	sess.SetPrivateRemote(auditAddrPort(fsConn))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	tb.Cleanup(cancel)
	leg.Start(context.Background(), 15*time.Second)

	lUfrag, lPwd := leg.LocalCredentials()
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
	browserConn, err := browser.Dial(ctx, lUfrag, lPwd)
	if err != nil {
		tb.Fatalf("browser ICE dial: %v", err)
	}
	tb.Cleanup(func() { _ = browserConn.Close() })

	browserCert, err := selfSignedForTest()
	if err != nil {
		tb.Fatal(err)
	}
	bDemux := newDemux(browserConn)
	tb.Cleanup(func() { _ = bDemux.Close() })
	bDTLS, err := dtls.Client(bDemux.dtls, bDemux.dtls.RemoteAddr(), &dtls.Config{
		Certificates:           []tls.Certificate{browserCert},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
		InsecureSkipVerify:     true,
	})
	if err != nil {
		tb.Fatal(err)
	}
	hs := make(chan error, 1)
	go func() { hs <- bDTLS.HandshakeContext(ctx) }()
	if err := sess.Start(ctx); err != nil {
		tb.Fatalf("session start: %v", err)
	}
	if err := <-hs; err != nil {
		tb.Fatalf("browser DTLS handshake: %v", err)
	}
	st, ok := bDTLS.ConnectionState()
	if !ok {
		tb.Fatal("browser has no DTLS state")
	}
	profile, _ := srtpProfileFor(dtls.SRTP_AES128_CM_HMAC_SHA1_80)
	keyLen, _ := profile.KeyLen()
	saltLen, _ := profile.SaltLen()
	m, err := st.ExportKeyingMaterial(srtpExporterLabel, nil, keyLen*2+saltLen*2)
	if err != nil {
		tb.Fatal(err)
	}
	out, err := newSRTPContextFromKeys(profile, m[:keyLen], m[keyLen*2:keyLen*2+saltLen])
	if err != nil {
		tb.Fatal(err)
	}
	in, err := newSRTPContextFromKeys(profile, m[keyLen:keyLen*2], m[keyLen*2+saltLen:])
	if err != nil {
		tb.Fatal(err)
	}
	return &auditBrowserCall{
		leg: leg, sess: sess, browserConn: browserConn, bDemux: bDemux,
		browserOut: out, browserIn: in, browserCert: browserCert,
		fsConn: fsConn, pub: pub, priv: priv,
	}
}
