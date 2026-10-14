package edge

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/hep"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// sip.SIPDebug and the tracer are unsynchronised process globals, and earlier
// tests leave sipgo goroutines that read SIPDebug. Production sets them in New
// before any Run; the suite sets them here, before any goroutine exists, so
// the race detector sees no write after a read. Tests without a HEP sender
// are unaffected: the tracer finds no route for their sockets.
func init() { installHEPTracer() }

// hepPkt is one HEP packet as the collector decoded it.
type hepPkt struct {
	proto     uint8
	src, dst  netip.AddrPort
	callID    string
	captureID uint32
	node      string
	payType   uint8
	payload   string
}

// firstLine is the SIP start line of the mirrored message.
func (p hepPkt) firstLine() string {
	l, _, _ := strings.Cut(p.payload, "\r\n")
	return l
}

// decodeHEP parses one HEPv3 datagram. The hep package's own decoder is
// test-only and unexported, so the edge suite carries a small one.
func decodeHEP(b []byte) (p hepPkt, ok bool) {
	if len(b) < 6 || string(b[:4]) != "HEP3" || int(binary.BigEndian.Uint16(b[4:6])) != len(b) {
		return p, false
	}
	var s4, d4 [4]byte
	var sp, dp uint16
	body := b[6:]
	for len(body) >= 6 {
		typ := binary.BigEndian.Uint16(body[2:4])
		l := int(binary.BigEndian.Uint16(body[4:6]))
		if l < 6 || l > len(body) {
			return p, false
		}
		data := body[6:l]
		body = body[l:]
		switch typ {
		case 0x02:
			p.proto = data[0]
		case 0x03:
			copy(s4[:], data)
		case 0x04:
			copy(d4[:], data)
		case 0x07:
			sp = binary.BigEndian.Uint16(data)
		case 0x08:
			dp = binary.BigEndian.Uint16(data)
		case 0x0b:
			p.payType = data[0]
		case 0x0c:
			p.captureID = binary.BigEndian.Uint32(data)
		case 0x0f:
			p.payload = string(data)
		case 0x11:
			p.callID = string(data)
		case 0x13:
			p.node = string(data)
		}
	}
	p.src = netip.AddrPortFrom(netip.AddrFrom4(s4), sp)
	p.dst = netip.AddrPortFrom(netip.AddrFrom4(d4), dp)
	return p, true
}

// hepCollector is a loopback HOMER: a UDP socket that records every packet.
type hepCollector struct {
	addr string
	conn *net.UDPConn

	mu   sync.Mutex
	pkts []hepPkt
}

func startHEPCollector(t *testing.T) *hepCollector {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", nextPort(t))
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatal(err)
	}
	c := &hepCollector{addr: addr, conn: conn}
	go func() {
		buf := make([]byte, 70000)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if p, ok := decodeHEP(buf[:n]); ok {
				c.mu.Lock()
				c.pkts = append(c.pkts, p)
				c.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return c
}

func (c *hepCollector) all() []hepPkt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]hepPkt(nil), c.pkts...)
}

// has reports whether a packet matches every non-zero criterion.
func (c *hepCollector) find(callID, linePrefix string, src, dst string) (hepPkt, bool) {
	for _, p := range c.all() {
		if callID != "" && p.callID != callID {
			continue
		}
		if linePrefix != "" && !strings.HasPrefix(p.firstLine(), linePrefix) {
			continue
		}
		if src != "" && p.src.String() != src {
			continue
		}
		if dst != "" && p.dst.String() != dst {
			continue
		}
		return p, true
	}
	return hepPkt{}, false
}

// await polls until a matching packet arrives.
func (c *hepCollector) await(t *testing.T, what, callID, linePrefix, src, dst string) hepPkt {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if p, ok := c.find(callID, linePrefix, src, dst); ok {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("no mirrored packet: %s (call-id %q, line %q, %s -> %s); got:\n%s", what, callID, linePrefix, src, dst, c.dump())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *hepCollector) dump() string {
	var b strings.Builder
	for _, p := range c.all() {
		fmt.Fprintf(&b, "  proto=%d %s -> %s call-id=%q %q\n", p.proto, p.src, p.dst, p.callID, p.firstLine())
	}
	return b.String()
}

// startHEPHarness is startHarness with the HEP mirror on, sending to a
// loopback collector over UDP.
func startHEPHarness(t *testing.T, webrtc, redact bool, carrierSources ...string) (*harness, *hepCollector) {
	t.Helper()
	col := startHEPCollector(t)
	sender, err := hep.New(hep.Options{Network: "udp", Addr: col.addr, CaptureID: 2001, NodeName: "edge-test"})
	if err != nil {
		t.Fatal(err)
	}
	// Registered before the harness's own cleanup, so it runs after the
	// proxy has stopped.
	t.Cleanup(func() { _ = sender.Close(t.Context()) })

	pubUDP := freePort(t)
	pubWS := 0
	if webrtc {
		pubWS = freeTCPPort(t)
	}
	priv := freePort(t)
	up := freePort(t)
	sources := harnessCarrierSources
	if len(carrierSources) > 0 {
		sources = carrierSources[0]
	}
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, pubWS, 0, nextMediaBase(t), sources) +
		fmt.Sprintf("hep:\n  address: %s\n  capture_id: 2001\n  node_name: edge-test\n  redact_auth: %v\n", col.addr, redact)
	h := newHarness(t, yaml, priv, WithHEP(sender))
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.run()
	return h, col
}

// checkHEPCommon asserts what every mirrored packet of the harness must
// satisfy.
func checkHEPCommon(t *testing.T, col *hepCollector) {
	t.Helper()
	for _, p := range col.all() {
		if p.captureID != 2001 || p.node != "edge-test" || p.payType != 1 {
			t.Errorf("packet %q: capture id %d, node %q, payload type %d", p.firstLine(), p.captureID, p.node, p.payType)
		}
		if strings.Contains(p.payload, arrivalHeader) {
			t.Errorf("mirrored payload carries the arrival marker:\n%s", p.payload)
		}
	}
}

// One UDP call mirrors every leg: the public INVITE in, the private INVITE
// out to the switch, the switch's 200 in, the 200 out to the phone, and the
// BYE both ways, with UDP as IP protocol 17 and the Call-ID on each.
func TestHEPMirrorsUDPCall(t *testing.T) {
	h, col := startHEPHarness(t, false, true)
	phone := newUDPClient(t)

	// The switch rings, then answers only once the phone has seen the 180, so
	// the 180 is never superseded by the 200 and its mirror is deterministic.
	// A 180 sent right before the 200 can be lost inside sipgo (#213).
	rang := make(chan struct{})
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		select {
		case <-rang:
		case <-time.After(5 * time.Second):
			t.Error("the phone never received the 180")
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		_ = tx.Respond(res)
		return true
	})

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(41000))
	invite.SetTransport("UDP")
	invite.SetDestination(h.publicUDP)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := phone.cli.TransactionRequest(ctx, invite)
	if err != nil {
		t.Fatalf("send INVITE: %v", err)
	}
	defer tx.Terminate()
	var res *sip.Response
	for res == nil {
		select {
		case r, ok := <-tx.Responses():
			if !ok {
				t.Fatal("INVITE: transaction closed with no final response")
			}
			if r.StatusCode == 180 {
				select {
				case <-rang:
				default:
					close(rang)
				}
			}
			if r.StatusCode >= 200 {
				res = r
			}
		case <-tx.Done():
			t.Fatalf("INVITE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("INVITE: timed out")
		}
	}
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d", res.StatusCode)
	}
	sendAck(t, phone, invite, res, h.publicUDP)
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("BYE: got %d", r.StatusCode)
	}
	h.fs.waitFor(sip.BYE, 1, 3*time.Second)
	waitForRelease(t, h)

	id := fsip.CallID(invite)
	pub, priv, up := h.publicUDP, h.privateSIP, h.upstream
	// The phone's UA sends from a socket of its own, so its end is read off
	// the mirrored INVITE and must be the end every later packet names.
	pin := col.await(t, "INVITE from phone", id, "INVITE ", "", pub)
	phoneAddr := pin.src.String()
	legs := []struct {
		what, line, src, dst string
	}{
		{"INVITE from phone", "INVITE ", phoneAddr, pub},
		{"INVITE to switch", "INVITE ", priv, up},
		{"200 from switch", "SIP/2.0 200", up, priv},
		{"200 to phone", "SIP/2.0 200", pub, phoneAddr},
		{"BYE from phone", "BYE ", phoneAddr, pub},
		{"BYE to switch", "BYE ", priv, up},
	}
	for _, l := range legs {
		p := col.await(t, l.what, id, l.line, l.src, l.dst)
		if p.proto != 17 {
			t.Errorf("%s: IP protocol %d, want 17", l.what, p.proto)
		}
	}
	col.await(t, "180 to phone", id, "SIP/2.0 180", pub, phoneAddr)
	col.await(t, "100 from switch", id, "SIP/2.0 100", up, priv)
	checkHEPCommon(t, col)
}

// A WebSocket call is reported as TCP (6), on the ws listener's address.
func TestHEPMirrorsWebSocketCall(t *testing.T) {
	h, col := startHEPHarness(t, true, true)
	browser := newWSClient(t)

	invite := browser.buildInvite("1001", "2002", "example.com", browserOfferSDP(51234))
	res := browser.do(t, invite, h.publicWS)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d", res.StatusCode)
	}
	sendAck(t, browser, invite, res, h.publicWS)
	if r := browser.do(t, buildBye(browser, invite, res), h.publicWS); r.StatusCode != 200 {
		t.Fatalf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)

	id := fsip.CallID(invite)
	in := col.await(t, "INVITE from browser", id, "INVITE ", "", h.publicWS)
	out := col.await(t, "200 to browser", id, "SIP/2.0 200", h.publicWS, "")
	if in.proto != 6 || out.proto != 6 {
		t.Errorf("ws protocol = %d/%d, want 6", in.proto, out.proto)
	}
	if in.src != out.dst {
		t.Errorf("browser end differs: request from %s, response to %s", in.src, out.dst)
	}
	// The switch legs of the same call are plain UDP, in one flow.
	sw := col.await(t, "INVITE to switch", id, "INVITE ", h.privateSIP, h.upstream)
	if sw.proto != 17 {
		t.Errorf("switch leg protocol = %d, want 17", sw.proto)
	}
	checkHEPCommon(t, col)
}

// Authorization is masked in the mirrored copy and only there.
func TestHEPRedactsAuthorization(t *testing.T) {
	for _, redact := range []bool{true, false} {
		t.Run(fmt.Sprintf("redact=%v", redact), func(t *testing.T) {
			h, col := startHEPHarness(t, false, redact)
			conn := auditUDP(t)
			port := auditUDPPort(conn)
			auditRawRequest(t, conn, h.publicUDP, fmt.Sprintf("REGISTER sip:example.com SIP/2.0\r\n"+
				"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-hep-auth;rport\r\n"+
				"Max-Forwards: 70\r\nFrom: <sip:1001@example.com>;tag=a\r\nTo: <sip:1001@example.com>\r\n"+
				"Call-ID: hep-auth\r\nCSeq: 2 REGISTER\r\nContact: <sip:1001@127.0.0.1:%d>\r\n"+
				"authorization: Digest username=\"1001\", response=\"cafef00dcafef00d\"\r\n"+
				"Proxy-Authorization: Digest username=\"1001\",\r\n response=\"decafbad\"\r\n"+
				"Content-Length: 0\r\n\r\n", port, port))

			in := col.await(t, "REGISTER from phone", "hep-auth", "REGISTER ", fmt.Sprintf("127.0.0.1:%d", port), h.publicUDP)
			fwd := col.await(t, "REGISTER to switch", "hep-auth", "REGISTER ", h.privateSIP, h.upstream)
			for _, p := range []hepPkt{in, fwd} {
				leaked := strings.Contains(p.payload, "cafef00d") || strings.Contains(p.payload, "decafbad")
				if leaked == redact {
					t.Errorf("redact=%v, leaked=%v:\n%s", redact, leaked, p.payload)
				}
				if redact && (!strings.Contains(p.payload, "uthorization: "+redactedValue+"\r\n") ||
					!strings.Contains(p.payload, "Content-Length: 0")) {
					t.Errorf("mask missing or message damaged:\n%s", p.payload)
				}
			}
			// The forwarded message itself is untouched.
			reg := h.fs.waitFor(sip.REGISTER, 1, 3*time.Second)
			if len(reg) == 0 || !strings.Contains(reg[0].GetHeader("Authorization").Value(), "cafef00dcafef00d") {
				t.Errorf("the switch did not receive the original Authorization header")
			}
		})
	}
}

// A request to the trusted private socket is stamped with the arrival
// marker after the mirror copy is taken, so the secret never reaches HOMER.
func TestHEPMirrorOmitsArrivalMarker(t *testing.T) {
	h, col := startHEPHarness(t, false, true)
	conn := auditUDP(t)
	port := auditUDPPort(conn)
	auditRawRequest(t, conn, h.privateSIP, fmt.Sprintf("OPTIONS sip:proxy@%s SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-hep-priv;rport\r\n"+
		"Max-Forwards: 70\r\nFrom: <sip:fs@127.0.0.1>;tag=p\r\nTo: <sip:proxy@%s>\r\n"+
		"Call-ID: hep-priv\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", h.privateSIP, port, h.privateSIP))
	if !auditRecvUntil(conn, 2*time.Second, func(b []byte) bool { return bytes.HasPrefix(b, []byte("SIP/2.0 200")) }) {
		t.Fatal("the private bind never answered")
	}
	col.await(t, "OPTIONS on the private socket", "hep-priv", "OPTIONS ", fmt.Sprintf("127.0.0.1:%d", port), h.privateSIP)
	col.await(t, "200 from the private socket", "hep-priv", "SIP/2.0 200", h.privateSIP, fmt.Sprintf("127.0.0.1:%d", port))
	checkHEPCommon(t, col)
}

// What the shield drops before parsing is not mirrored: a banned source's
// datagrams never reach the collector.
func TestHEPDoesNotMirrorBannedSource(t *testing.T) {
	h, col := startHEPHarness(t, false, true, "") // a carrier source is never banned
	conn := auditUDP(t)
	port := auditUDPPort(conn)
	self := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port))
	req := func(callID, ua string) string {
		return fmt.Sprintf("OPTIONS sip:x@127.0.0.1 SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-%s;rport\r\n"+
			"Max-Forwards: 70\r\nFrom: <sip:s@127.0.0.1>;tag=scan\r\nTo: <sip:x@127.0.0.1>\r\n"+
			"Call-ID: %s\r\nCSeq: 1 OPTIONS\r\nUser-Agent: %s\r\nContent-Length: 0\r\n\r\n", port, callID, callID, ua)
	}
	// The scanner datagram itself passed the filter; the ban follows it.
	auditRawRequest(t, conn, h.publicUDP, req("hep-scan-1", "friendly-scanner"))
	col.await(t, "the datagram that earned the ban", "hep-scan-1", "OPTIONS ", self.String(), h.publicUDP)
	deadline := time.Now().Add(2 * time.Second)
	for !h.srv.currentShield().BannedFrom(self, "udp") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !h.srv.currentShield().BannedFrom(self, "udp") {
		t.Fatal("scanner was not banned")
	}
	auditRawRequest(t, conn, h.publicUDP, req("hep-scan-2", "sipcli"))

	// A later packet from another socket proves the collector kept up.
	other := auditUDP(t)
	auditRawRequest(t, other, h.publicUDP, req("hep-after", "sipcli"))
	col.await(t, "a packet sent after the banned one", "hep-after", "OPTIONS ", "", h.publicUDP)
	if p, ok := col.find("hep-scan-2", "", "", ""); ok {
		t.Errorf("a banned source's datagram was mirrored: %q", p.firstLine())
	}
}

// Behind 1:1 NAT the local end is reported as public.ip, not public.bind.
func TestHEPReportsPublicIPBehindNAT(t *testing.T) {
	col := startHEPCollector(t)
	sender, err := hep.New(hep.Options{Network: "udp", Addr: col.addr, CaptureID: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close(t.Context())
	m := &hepMirror{sender: sender, bind: netip.MustParseAddr("172.31.5.10"), pub: netip.MustParseAddr("203.0.113.7")}
	msg := []byte("OPTIONS sip:x SIP/2.0\r\nCall-ID: nat-1\r\n\r\n")
	remote := netip.MustParseAddrPort("198.51.100.4:5070")
	m.capture(17, netip.MustParseAddrPort("172.31.5.10:5060"), remote, true, msg)
	m.capture(17, netip.MustParseAddrPort("172.31.5.10:5060"), remote, false, msg)
	// The private socket is not translated.
	m.capture(17, netip.MustParseAddrPort("10.77.0.2:5060"), netip.MustParseAddrPort("10.77.0.10:5060"), false, msg)
	col.await(t, "inbound", "nat-1", "OPTIONS", "198.51.100.4:5070", "203.0.113.7:5060")
	col.await(t, "outbound", "nat-1", "OPTIONS", "203.0.113.7:5060", "198.51.100.4:5070")
	col.await(t, "private", "nat-1", "OPTIONS", "10.77.0.2:5060", "10.77.0.10:5060")
}

func TestHEPCallIDOf(t *testing.T) {
	for name, tc := range map[string]struct{ msg, want string }{
		"long":          {"INVITE sip:a@b SIP/2.0\r\nCall-ID: abc@host\r\n\r\n", "abc@host"},
		"mixed case":    {"INVITE sip:a@b SIP/2.0\r\ncAlL-iD:   abc  \r\n\r\n", "abc"},
		"compact":       {"INVITE sip:a@b SIP/2.0\r\nv: x\r\ni: abc\r\n\r\n", "abc"},
		"bare LF":       {"INVITE sip:a@b SIP/2.0\nCall-ID: abc\n\n", "abc"},
		"leading CRLF":  {"\r\n\r\nINVITE sip:a@b SIP/2.0\r\nCall-ID: abc\r\n\r\n", "abc"},
		"none":          {"INVITE sip:a@b SIP/2.0\r\nVia: x\r\n\r\n", ""},
		"in the body":   {"INVITE sip:a@b SIP/2.0\r\nVia: x\r\n\r\nCall-ID: nope\r\n", ""},
		"start line":    {"Call-ID: x:y\r\n", ""},
		"keep-alive":    {"\r\n\r\n", ""},
		"empty":         {"", ""},
		"folded name":   {"INVITE sip:a@b SIP/2.0\r\n Call-ID: nope\r\n\r\n", ""},
		"no terminator": {"INVITE sip:a@b SIP/2.0\r\nCall-ID: abc", "abc"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := callIDOf([]byte(tc.msg)); got != tc.want {
				t.Errorf("callIDOf = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHEPRedactAuthHeaders(t *testing.T) {
	in := "REGISTER sip:a SIP/2.0\r\nCall-ID: c\r\nAUTHORIZATION: Digest response=\"s3cret\",\r\n\tnonce=\"n\"\r\n" +
		"proxy-authorization:Digest response=\"s3cret2\"\r\nVia: v\r\nContent-Length: 12\r\n\r\nAuthorization: body"
	orig := []byte(in)
	got := string(redactAuthHeaders(orig))
	want := "REGISTER sip:a SIP/2.0\r\nCall-ID: c\r\nAUTHORIZATION: REDACTED\r\n" +
		"proxy-authorization: REDACTED\r\nVia: v\r\nContent-Length: 12\r\n\r\nAuthorization: body"
	if got != want {
		t.Errorf("redacted:\n%q\nwant:\n%q", got, want)
	}
	if string(orig) != in {
		t.Error("the input was modified")
	}
	// Nothing to mask, or not a message at all: returned as a copy.
	for _, s := range []string{"", "x", "\r\n", "INVITE sip:a SIP/2.0\r\nCall-ID: c\r\n\r\n"} {
		if got := string(redactAuthHeaders([]byte(s))); got != s {
			t.Errorf("redactAuthHeaders(%q) = %q", s, got)
		}
	}
}

func TestHEPNextStreamMessage(t *testing.T) {
	a := "OPTIONS sip:a SIP/2.0\r\nCall-ID: a\r\nContent-Length: 0\r\n\r\n"
	b := "MESSAGE sip:b SIP/2.0\r\nCall-ID: b\r\nl: 5\r\n\r\nhello"
	data := []byte("\r\n" + a + b + "OPTIONS sip:c SIP/2.0\r\nCall-ID: c\r\nContent-Length: 4\r\n\r\nab")
	m1, rest := nextStreamMessage(data)
	if string(m1) != a {
		t.Fatalf("first = %q", m1)
	}
	m2, rest := nextStreamMessage(rest)
	if string(m2) != b {
		t.Fatalf("second = %q", m2)
	}
	if m3, _ := nextStreamMessage(rest); m3 != nil {
		t.Errorf("a partial message was returned: %q", m3)
	}
	if m, _ := nextStreamMessage([]byte("\r\n\r\n")); m != nil {
		t.Errorf("keep-alive returned %q", m)
	}
	if m, _ := nextStreamMessage([]byte("OPTIONS sip:a SIP/2.0\r\nCall-ID: a\r\n")); m != nil {
		t.Errorf("headers with no end returned %q", m)
	}
}

// Hostile bytes never panic the capture path.
func FuzzHEPCapture(f *testing.F) {
	f.Add([]byte("INVITE sip:a SIP/2.0\r\nCall-ID: x\r\nAuthorization: a\r\n b\r\n\r\n"))
	f.Add([]byte("\r\n:\r\n\n\n i:\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		callIDOf(b)
		out := redactAuthHeaders(b)
		if len(out) > len(b)+64*(1+bytes.Count(b, []byte("\n"))) {
			t.Fatalf("redaction grew the message: %d -> %d", len(b), len(out))
		}
		rest := b
		for i := 0; i < len(b)+1; i++ {
			m, r := nextStreamMessage(rest)
			if m == nil {
				break
			}
			if len(r) >= len(rest) {
				t.Fatal("nextStreamMessage made no progress")
			}
			rest = r
		}
	})
}
