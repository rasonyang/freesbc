package edge

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/shield"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Tests for the malformed-datagram strike (issue #190): the read filter
// scans public UDP and WS/WSS reads with fsip.Malformed and feeds the
// shield's admission_ban budget. Timing-based over real UDP loopback:
// re-run once before treating a flake as failure.

// scanValid is a corpus every scan must pass and sipgo must parse.
var scanValid = []string{
	"INVITE sip:b@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n" +
		"From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n" +
		"Content-Length: 4\r\n\r\nbody",
	"OPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\n\r\n",
	"OPTIONS sip:x sip/2.0\r\nCall-ID: c\r\n\r\n",
	"OPTIONS sip:x SIP/2.0\r\nSubject: a\r\n  folded line\r\n\tmore\r\nCall-ID: c\r\n\r\n",
	"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\n\r\n",
	"SIP/2.0 180 Ringing\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\n\r\n",
	"MESSAGE sip:x SIP/2.0\r\nCall-ID: c\r\n\r\nno colon\r\nin the body",
	// found by the fuzzer: the colon arrives on a continuation line
	" A:0 SIP\r\n0\r\n :\r\n\r\n",
}

// scanKeepAlive is read and discarded by sipgo before it parses anything.
var scanKeepAlive = []string{"\r\n", "\r\n\r\n", "\x00\x00"}

// scanBad is a corpus the scan flags.
var scanBad = []string{
	"hello world",
	"INVITE sip:a@b\r\n\r\n",
	"NOTSIP 1 Authorization: x\r\n\r\n",
	"INVITE sip:a Sip/2.0\r\nCall-ID: c\r\n\r\n",
	"OPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\n",
	"OPTIONS sip:x SIP/2.0",
	"OPTIONS sip:x SIP/2.0\rCall-ID: c\r\n\r\n",
	"OPTIONS sip:x SIP/2.0\nCall-ID: c\n\n",
	"\r\nOPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\n\r\n",
	"OPTIONS sip:x SIP/2.0\r\nCall-ID c\r\n\r\n",
	"OPTIONS sip:x SIP/2.0\r\n no colon\r\n\r\n",
	"OPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\nbroken\r\n\r\n",
	"\x01\x02\x03\xff\xfe",
}

// If a sipgo upgrade changes what its parser accepts, this fails: a flagged
// input that sipgo now parses would strike a valid sender. It parses with
// the same call sipgo's UDP and WS transports make.
func TestSipgoMalformedScanContract(t *testing.T) {
	p := sip.NewParser()
	for _, in := range scanBad {
		if !fsip.Malformed([]byte(in)) {
			t.Errorf("scan passed %q", in)
		}
		if _, err := p.ParseSIP([]byte(in)); err == nil {
			t.Errorf("sipgo parses %q, which the scan flags as malformed", in)
		}
	}
	for _, in := range scanValid {
		if fsip.Malformed([]byte(in)) {
			t.Errorf("scan flags valid %q", in)
		}
		if _, err := p.ParseSIP([]byte(in)); err != nil {
			t.Errorf("sipgo rejects %q: %v", in, err)
		}
	}
	for _, in := range scanKeepAlive {
		if fsip.Malformed([]byte(in)) {
			t.Errorf("scan flags keep-alive %q", in)
		}
	}
}

// FuzzMalformedScan: whenever the scan flags an input, sipgo's parser
// rejects it (the scan is a strict subset of the parser's rejections).
func FuzzMalformedScan(f *testing.F) {
	for _, in := range scanValid {
		f.Add([]byte(in))
	}
	for _, in := range scanBad {
		f.Add([]byte(in))
	}
	p := sip.NewParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		if !fsip.Malformed(data) {
			return
		}
		if _, err := p.ParseSIP(data); err == nil {
			t.Fatalf("scan flags %q but sipgo parses it", data)
		}
	})
}

// sendRaw writes one datagram from a fresh socket (a new source port).
func sendMalformedProbe(t *testing.T, h *harness, data []byte) {
	t.Helper()
	conn := auditUDP(t)
	pub, err := net.ResolveUDPAddr("udp", h.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDP(data, pub); err != nil {
		t.Fatal(err)
	}
}

func waitOffenderStrikes(t *testing.T, h *harness, reason string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		top, _ := h.srv.currentShield().Offenders(10)
		got := 0
		for _, o := range top {
			if o.Reason == reason {
				got = o.Strikes
			}
		}
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("offender %s strikes = %d, want %d (%+v)", reason, got, want, top)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Malformed datagrams above shield.admission_ban ban the source on UDP
// only; below it nothing happens, and once banned the datagrams no longer
// reach the parser.
func TestMalformedDatagramsBanUDPSource(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "3/5m")
	for i := 0; i < 3; i++ {
		sendMalformedProbe(t, h, garbage(i))
	}
	waitOffenderStrikes(t, h, shield.StrikeMalformedUDP, 3)
	if bannedLoopbackUDP(h) {
		t.Fatal("banned at the threshold; want only past it")
	}
	sendMalformedProbe(t, h, garbage(4))
	deadline := time.Now().Add(5 * time.Second)
	for !bannedLoopbackUDP(h) {
		if time.Now().After(deadline) {
			t.Fatal("the 4th malformed datagram did not ban the source")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.srv.currentShield().BannedFrom(netip.AddrPortFrom(guardSrc, 5999), "tcp") {
		t.Error("a UDP malformed ban covers tcp")
	}
	page, _, _ := h.srv.Bans(10, 0)
	if len(page) != 1 || page[0].Reason != shield.BanReasonMalformed || page[0].Kind != shield.BanKindUDPIP {
		t.Errorf("bans = %+v", page)
	}
	time.Sleep(100 * time.Millisecond)
	before := h.parseFailures("UDP")
	for i := 0; i < 3; i++ {
		sendMalformedProbe(t, h, garbage(10+i))
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.parseFailures("UDP"); got != before {
		t.Errorf("parse failures after the ban = %d, want %d (read filter drops first)", got, before)
	}
}

// A source alternating admission drops and malformed datagrams is banned
// when the two together pass the one shared budget.
func TestMalformedAndAdmissionShareBudget(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "3/5m")
	scanOnce(t, h)
	sendMalformedProbe(t, h, garbage(1))
	scanOnce(t, h)
	waitDrops(t, h, 2)
	waitOffenderStrikes(t, h, shield.StrikeMalformedUDP, 1)
	if bannedLoopbackUDP(h) {
		t.Fatal("banned at the shared threshold")
	}
	sendMalformedProbe(t, h, garbage(2))
	deadline := time.Now().Add(5 * time.Second)
	for !bannedLoopbackUDP(h) {
		if time.Now().After(deadline) {
			t.Fatal("alternating strikes past the shared budget did not ban")
		}
		time.Sleep(10 * time.Millisecond)
	}
	top, _ := h.srv.currentShield().Offenders(10)
	seen := map[string]int{}
	for _, o := range top {
		seen[o.Reason] = o.Strikes
	}
	if seen[shield.StrikeAdmissionUDP] != 2 || seen[shield.StrikeMalformedUDP] != 2 {
		t.Errorf("offenders = %+v, want admission_udp 2 and malformed_udp 2", top)
	}
}

// A valid message or a keep-alive never strikes.
func TestMalformedScanSparesValidTraffic(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "1/5m")
	for i := 0; i < 5; i++ {
		sendMalformedProbe(t, h, rawOptions(auditUDP(t).LocalAddr(), i))
		sendMalformedProbe(t, h, []byte("\r\n\r\n"))
	}
	time.Sleep(300 * time.Millisecond)
	if _, total := h.srv.currentShield().Offenders(10); total != 0 {
		t.Errorf("offenders = %d, want none for valid traffic", total)
	}
}

// An IP holding a live registration is never struck by its malformed
// datagrams.
func TestMalformedSparesRegisteredIP(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "1/5m")
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	for i := 0; i < 5; i++ {
		sendMalformedProbe(t, h, garbage(i))
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.parseFailures("UDP") < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if bannedLoopbackUDP(h) {
		t.Fatal("an IP with a live registration was banned for malformed datagrams")
	}
	if _, total := h.srv.currentShield().Offenders(10); total != 0 {
		t.Errorf("offenders = %d, want none", total)
	}
}

// A carrier source is never struck.
func TestMalformedSparesCarrierSource(t *testing.T) {
	h := startHarnessFull(t, false, false, "127.0.0.0/8")
	setAdmissionBan(h, "1/5m")
	for i := 0; i < 5; i++ {
		sendMalformedProbe(t, h, garbage(i))
	}
	time.Sleep(300 * time.Millisecond)
	if bannedLoopbackUDP(h) {
		t.Fatal("a carrier source was banned for malformed datagrams")
	}
	if _, total := h.srv.currentShield().Offenders(10); total != 0 {
		t.Errorf("offenders = %d, want none for a carrier source", total)
	}
}

// Filter level: a ws/wss frame strikes in the stream scope, a tcp/tls chunk
// and the trusted private socket never strike.
func TestMalformedFilterScopes(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "50/5m")
	filter := h.srv.readFilter()
	remote := func(port int) net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port} }
	public := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:25001"))
	read := func(tr string, local net.Addr) {
		if _, err := filter(sip.TransportReadProps{Transport: tr, LocalAddr: local, RemoteAddr: remote(7000)},
			[]byte("junk")); err != nil {
			t.Fatal(err)
		}
	}
	read("tcp", public)
	read("tls", public)
	read("udp", net.UDPAddrFromAddrPort(h.srv.privAddr))
	if _, total := h.srv.currentShield().Offenders(10); total != 0 {
		t.Fatalf("tcp, tls or the private socket struck: %d", total)
	}
	read("wss", public)
	read("ws", public)
	read("udp", public)
	top, _ := h.srv.currentShield().Offenders(10)
	seen := map[string]int{}
	for _, o := range top {
		seen[o.Reason] = o.Strikes
	}
	if seen[shield.StrikeMalformed] != 2 || seen[shield.StrikeMalformedUDP] != 1 {
		t.Errorf("offenders = %+v, want malformed 2 (ws, wss) and malformed_udp 1", top)
	}
}
