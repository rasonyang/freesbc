package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/config"
	"github.com/freesbc/freesbc/sdpx"
)

// This file drives FreeSBC against a REAL FreeSWITCH. It is opt-in:
//
//	FREESBC_FS_INTEROP=1 \
//	FREESBC_FS_ADDR=192.168.31.55:5060 \
//	FREESBC_FS_LOCAL=192.168.31.55 \
//	FREESBC_FS_USER=1000 FREESBC_FS_PASS='...' \
//	go test ./proxy/ -run TestFreeSWITCH -v
//
// The fake switch in harness_test.go cannot answer the questions that
// actually decide whether this works in production, because they are all
// questions about sofia's behaviour rather than about SIP in general:
//
//   - does sofia preserve an unknown URI parameter (the fsbc= binding
//     token) from a registered Contact into the Request-URI of the INVITE
//     it later sends to that contact? The entire inbound-call path depends
//     on it;
//   - does it accept a REGISTER whose Contact names a host other than the
//     sender, with two Vias in front of it;
//   - does a hangup on the switch side actually traverse the proxy?
//
// A failure here is a real deployment failure, which is why it is a test
// and not a note in the README.

func fsEnv(t *testing.T) (addr, local, user, pass string) {
	t.Helper()
	if os.Getenv("FREESBC_FS_INTEROP") != "1" {
		t.Skip("set FREESBC_FS_INTEROP=1 (and FREESBC_FS_ADDR/LOCAL/USER/PASS) to run against a live FreeSWITCH")
	}
	addr = os.Getenv("FREESBC_FS_ADDR")
	local = os.Getenv("FREESBC_FS_LOCAL")
	user = os.Getenv("FREESBC_FS_USER")
	pass = os.Getenv("FREESBC_FS_PASS")
	if addr == "" || local == "" || user == "" || pass == "" {
		t.Fatal("FREESBC_FS_ADDR, FREESBC_FS_LOCAL, FREESBC_FS_USER and FREESBC_FS_PASS are all required")
	}
	return
}

// fsHarness is startHarness against a real switch: the proxy binds the
// host's LAN address (so FreeSWITCH's replies come from an address the
// proxy recognises as upstream) and there is no fake switch.
type fsHarness struct {
	srv        *Server
	store      *config.Store
	publicUDP  string
	privateSIP string
	cancel     context.CancelFunc
	done       chan struct{}
}

func startFSHarness(t *testing.T, upstream, localIP string) *fsHarness {
	t.Helper()
	pubPort := nextPort(t)
	privPort := nextPort(t)
	mediaBase := nextMediaBase()

	yaml := fmt.Sprintf(`
network:
  public:
    bind_ip: %[3]s
    advertised_ip: %[3]s
  private:
    bind_ip: %[3]s
    advertised_ip: %[3]s
sip:
  public:
    udp: {enabled: true, bind: "%[3]s:%[1]d"}
  private:
    bind: "%[3]s:%[2]d"
  upstream:
    address: %[4]s
rtp:
  public:  {bind_ip: %[3]s, advertised_ip: %[3]s, port_min: %[5]d, port_max: %[6]d}
  private: {bind_ip: %[3]s, advertised_ip: %[3]s, port_min: %[7]d, port_max: %[8]d}
listen:
  media:
    rtp_timeout: 60s
shield:
  rate_limit: "5000/s per_ip"
`, pubPort, privPort, localIP, upstream, mediaBase, mediaBase+199, mediaBase+200, mediaBase+399)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("interop config: %v", err)
	}
	store := config.NewStore(cfg)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv, err := New(store, log)
	if err != nil {
		t.Fatal(err)
	}
	h := &fsHarness{
		srv: srv, store: store,
		publicUDP:  fmt.Sprintf("%s:%d", localIP, pubPort),
		privateSIP: fmt.Sprintf("%s:%d", localIP, privPort),
		done:       make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("proxy Run: %v", err)
		}
	}()
	select {
	case <-srv.Ready():
	case <-time.After(10 * time.Second):
		t.Fatal("proxy never became ready")
	}
	t.Cleanup(func() {
		cancel()
		<-h.done
	})
	return h
}

// fsPhone is a SIP/UDP phone bound to a specific local address, so its
// source address is distinguishable from FreeSWITCH's.
type fsPhone struct {
	*client
}

func newFSPhone(t *testing.T, localIP string) *fsPhone {
	t.Helper()
	c := newClientBase(t, "udp")
	port := nextPort(t)
	c.local = fmt.Sprintf("%s:%d", localIP, port)
	addr, err := net.ResolveUDPAddr("udp", c.local)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	prev := c.cancel
	c.cancel = func() { cancel(); prev() }
	go func() { <-ctx.Done(); conn.Close() }()
	go func() { _ = c.srv.TransportLayer().ServeUDP(conn) }()
	return &fsPhone{client: c}
}

// registerWithDigest performs the full two-step REGISTER through the
// proxy, answering the challenge sofia sends.
func (p *fsPhone) registerWithDigest(t *testing.T, user, pass, domain, dest string, expires int) *sip.Response {
	t.Helper()
	req := p.buildRegister(user, domain, expires, "")
	req.SetTransport("UDP")
	req.SetDestination(dest)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := p.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("REGISTER: %v", err)
	}
	var challenge *sip.Response
	func() {
		defer tx.Terminate()
		for {
			select {
			case res, ok := <-tx.Responses():
				if !ok {
					t.Fatal("REGISTER: no final response")
				}
				if res.StatusCode >= 200 {
					challenge = res
					return
				}
			case <-tx.Done():
				t.Fatalf("REGISTER: %v", tx.Err())
			case <-ctx.Done():
				t.Fatal("REGISTER timed out")
			}
		}
	}()
	if challenge.StatusCode != 401 && challenge.StatusCode != 407 {
		return challenge
	}
	// Answer the challenge. sipgo computes the digest over the request's
	// own Request-URI — which is exactly why the proxy must not rewrite it.
	authTx, err := p.cli.TransactionDigestAuth(ctx, req, challenge, sipgo.DigestAuth{Username: user, Password: pass})
	if err != nil {
		t.Fatalf("REGISTER digest: %v", err)
	}
	defer authTx.Terminate()
	for {
		select {
		case res, ok := <-authTx.Responses():
			if !ok {
				t.Fatal("authenticated REGISTER: no final response")
			}
			if res.StatusCode >= 200 {
				return res
			}
		case <-authTx.Done():
			t.Fatalf("authenticated REGISTER: %v", authTx.Err())
		case <-ctx.Done():
			t.Fatal("authenticated REGISTER timed out")
		}
	}
}

func fsCli(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("/usr/local/freeswitch/bin/fs_cli", append([]string{"-x"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("fs_cli %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// TestFreeSWITCHRegistrationStoresProxyContact is the question the fake
// switch cannot answer: does sofia accept a proxied REGISTER, and does it
// store the SBC's contact WITH the binding token intact?
func TestFreeSWITCHRegistrationStoresProxyContact(t *testing.T) {
	addr, local, user, pass := fsEnv(t)
	h := startFSHarness(t, addr, local)
	phone := newFSPhone(t, local)

	domain := strings.Split(addr, ":")[0]
	res := phone.registerWithDigest(t, user, pass, domain, h.publicUDP, 300)
	if res.StatusCode != 200 {
		t.Fatalf("REGISTER through the proxy: got %d, want 200\n%s", res.StatusCode, res.String())
	}

	// FreeSBC recorded a binding...
	bindings := h.srv.loc.ByAOR(strings.ToLower(user + "@" + domain))
	if len(bindings) != 1 {
		t.Fatalf("proxy bindings = %d, want 1", len(bindings))
	}
	token := bindings[0].Token

	// ...and sofia stored the SBC's contact, token and all.
	regs := fsCli(t, "sofia status profile internal reg")
	if !strings.Contains(regs, h.srv.topo.private.advIP.String()) {
		t.Errorf("sofia did not store the SBC's private address:\n%s", regs)
	}
	if !strings.Contains(regs, contactTokenParam+"="+token) {
		t.Errorf("sofia did not preserve the binding token %q in the stored contact — "+
			"inbound calls could not be routed to a specific device:\n%s", token, regs)
	}
	t.Logf("sofia registration:\n%s", regs)

	// Un-register so the switch is left as we found it.
	phone.registerWithDigest(t, user, pass, domain, h.publicUDP, 0)
}

// TestFreeSWITCHInboundCallAndHangup is Blocker A live: FreeSWITCH calls
// the registered contact through the proxy, and then hangs up. Both the
// INVITE and the BYE have to traverse FreeSBC.
func TestFreeSWITCHInboundCallAndHangup(t *testing.T) {
	addr, local, user, pass := fsEnv(t)
	h := startFSHarness(t, addr, local)
	phone := newFSPhone(t, local)
	domain := strings.Split(addr, ":")[0]

	if res := phone.registerWithDigest(t, user, pass, domain, h.publicUDP, 300); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	t.Cleanup(func() { phone.registerWithDigest(t, user, pass, domain, h.publicUDP, 0) })

	// The phone answers with its own media.
	rtp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(local)})
	if err != nil {
		t.Fatal(err)
	}
	defer rtp.Close()
	rtpPort := rtp.LocalAddr().(*net.UDPAddr).Port

	answered := make(chan *sip.Request, 1)
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(rtpPort)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI(user)})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
		select {
		case answered <- req.Clone():
		default:
		}
	})

	// Park the far end so the call stays up until we hang it up.
	out := fsCli(t, fmt.Sprintf("originate {origination_caller_id_number=5551212}user/%s@%s &park", user, domain))
	t.Logf("originate: %s", strings.TrimSpace(out))
	if !strings.Contains(out, "+OK") {
		t.Fatalf("originate failed: %s", out)
	}
	uuid := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "+OK"))

	var inbound *sip.Request
	select {
	case inbound = <-answered:
	case <-time.After(15 * time.Second):
		t.Fatal("the INVITE from FreeSWITCH never reached the phone")
	}

	// The Request-URI the phone saw must name the phone, not the SBC.
	if inbound.Recipient.User != user {
		t.Errorf("Request-URI user = %q, want %q", inbound.Recipient.User, user)
	}
	// And its media must be the SBC's, not FreeSWITCH's.
	offer, err := sdpx.Parse(inbound.Body())
	if err != nil {
		t.Fatalf("inbound offer unparseable: %v\n%s", err, inbound.Body())
	}
	pubRange := h.store.Current().RTP.Public
	if offer.Audio.Port < pubRange.PortMin || offer.Audio.Port > pubRange.PortMax {
		t.Errorf("the phone was offered media on %d, outside the SBC's public pool %d-%d — "+
			"media would bypass the SBC", offer.Audio.Port, pubRange.PortMin, pubRange.PortMax)
	}

	drain(phone.inbound)

	// Hang up from the switch: the BYE must traverse the proxy.
	fsCli(t, "uuid_kill "+uuid)
	deadline := time.After(15 * time.Second)
	for {
		select {
		case got := <-phone.inbound:
			if got.Method == sip.BYE {
				return // success
			}
		case <-deadline:
			t.Fatal("the BYE from FreeSWITCH never reached the phone — the call would hang " +
				"until the media watchdog fired")
		}
	}
}

// TestFreeSWITCHMediaEcho is acceptance criteria 4, 6, 7 and 8 against the
// real thing: FreeSWITCH runs its echo application, the phone sends RTP
// through the SBC, and the same audio must come back through the SBC.
//
// It proves the whole media path at once — that FreeSWITCH accepted the
// SDP FreeSBC built for it, that it is sending to the SBC's private port
// rather than to the phone, and that the relay carries payload in both
// directions untranscoded.
func TestFreeSWITCHMediaEcho(t *testing.T) {
	addr, local, user, pass := fsEnv(t)
	h := startFSHarness(t, addr, local)
	phone := newFSPhone(t, local)
	domain := strings.Split(addr, ":")[0]

	if res := phone.registerWithDigest(t, user, pass, domain, h.publicUDP, 300); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	t.Cleanup(func() { phone.registerWithDigest(t, user, pass, domain, h.publicUDP, 0) })

	rtp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(local)})
	if err != nil {
		t.Fatal(err)
	}
	defer rtp.Close()
	rtpPort := rtp.LocalAddr().(*net.UDPAddr).Port

	// Answer with PCMU only, so what comes back is unambiguous.
	answerSDP := fmt.Sprintf("v=0\r\no=phone 1 1 IN IP4 %[1]s\r\ns=-\r\nc=IN IP4 %[1]s\r\nt=0 0\r\n"+
		"m=audio %[2]d RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"+
		"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=sendrecv\r\n", local, rtpPort)

	gotInvite := make(chan *sip.Request, 1)
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(answerSDP))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI(user)})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
		select {
		case gotInvite <- req.Clone():
		default:
		}
	})

	out := fsCli(t, fmt.Sprintf("originate user/%s@%s &echo", user, domain))
	if !strings.Contains(out, "+OK") {
		t.Fatalf("originate: %s", out)
	}
	uuid := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "+OK"))
	t.Cleanup(func() {
		_, _ = exec.Command("/usr/local/freeswitch/bin/fs_cli", "-x", "uuid_kill "+uuid).CombinedOutput()
	})

	var inbound *sip.Request
	select {
	case inbound = <-gotInvite:
	case <-time.After(15 * time.Second):
		t.Fatal("the INVITE never reached the phone")
	}
	offer, err := sdpx.Parse(inbound.Body())
	if err != nil {
		t.Fatalf("offer unparseable: %v", err)
	}
	sbcMedia := &net.UDPAddr{IP: net.ParseIP(local), Port: offer.Audio.Port}

	// FreeSWITCH's echo reflects whatever it receives. Send a marked PCMU
	// packet through the SBC and wait for it to come back through the SBC.
	// Retry: echo needs a moment to come up, and the first packets also
	// arm the relay's latches.
	want := rtpPacket(0, 4242, 160)
	for i := range want[12:] {
		want[12+i] = byte(i % 251) // a payload nothing else would produce
	}
	buf := make([]byte, 2000)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := rtp.WriteToUDP(want, sbcMedia); err != nil {
			t.Fatal(err)
		}
		_ = rtp.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, src, err := rtp.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		// Whatever arrives must arrive FROM the SBC — never from
		// FreeSWITCH's own media address (acceptance 10).
		if src.Port != offer.Audio.Port {
			t.Fatalf("media arrived from %s, not from the SBC's public port %d — "+
				"the media path bypassed the SBC", src, offer.Audio.Port)
		}
		if n >= 12 && string(buf[12:n]) == string(want[12:]) {
			st := h.srv.metrics.Snapshot()
			t.Logf("echo returned through the SBC; media counters: %+v", st)
			return
		}
	}
	t.Fatal("audio never came back through the SBC")
}

// TestFreeSWITCHOutboundInvite drives the public→private direction against
// real sofia: a registered phone places a call, and the INVITE FreeSBC
// builds must be one FreeSWITCH accepts, parses and routes.
//
// The extension is deliberately unrouteable, because this machine's
// dialplan has no echo target reachable from a phone. That still settles
// the question this test exists for — whether sofia accepts the request
// line, the two Vias, the Record-Route pair, the rewritten Contact and the
// generated SDP — since a rejection at the dialplan can only happen AFTER
// all of that parsed. A malformed request comes back 400/482 or not at
// all; a routing miss comes back as a clean call failure.
func TestFreeSWITCHOutboundInvite(t *testing.T) {
	addr, local, user, pass := fsEnv(t)
	h := startFSHarness(t, addr, local)
	phone := newFSPhone(t, local)
	domain := strings.Split(addr, ":")[0]

	if res := phone.registerWithDigest(t, user, pass, domain, h.publicUDP, 300); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	t.Cleanup(func() { phone.registerWithDigest(t, user, pass, domain, h.publicUDP, 0) })

	rtp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(local)})
	if err != nil {
		t.Fatal(err)
	}
	defer rtp.Close()
	rtpPort := rtp.LocalAddr().(*net.UDPAddr).Port

	invite := phone.buildInvite(user, "9999", domain, fmt.Sprintf(
		"v=0\r\no=phone 1 1 IN IP4 %[1]s\r\ns=-\r\nc=IN IP4 %[1]s\r\nt=0 0\r\n"+
			"m=audio %[2]d RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"+
			"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=sendrecv\r\n", local, rtpPort))
	res := phone.do(t, invite, h.publicUDP)

	// Anything in the 4xx-6xx range means sofia understood the request and
	// declined it at the dialplan. A 400 (Bad Request) or 482 (Loop
	// Detected) would mean it did not — those are the failures worth
	// naming.
	switch {
	case res.StatusCode == 400:
		t.Fatalf("FreeSWITCH rejected the proxied INVITE as malformed:\n%s", res.String())
	case res.StatusCode == 482:
		t.Fatalf("FreeSWITCH detected a loop — the proxy's Via or Record-Route is wrong:\n%s", res.String())
	case res.StatusCode >= 400 && res.StatusCode < 700:
		t.Logf("FreeSWITCH parsed and routed the proxied INVITE, declining it as expected: %d %s",
			res.StatusCode, res.Reason)
	case res.StatusCode == 200:
		t.Logf("unexpectedly answered; hanging up")
		sendAck(t, phone.client, invite, res, h.publicUDP)
		phone.do(t, buildBye(phone.client, invite, res), h.publicUDP)
	default:
		t.Fatalf("unexpected response %d", res.StatusCode)
	}

	// Whatever the outcome, the media the call reserved must be gone.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pub, _ := h.srv.pubPool.Stats()
		priv, _ := h.srv.privPool.Stats()
		if pub == 0 && priv == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	pub, _ := h.srv.pubPool.Stats()
	priv, _ := h.srv.privPool.Stats()
	t.Errorf("media leaked after a failed call: public=%d private=%d", pub, priv)
}
