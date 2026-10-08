package edge

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
)

// These tests drive the tcp and tls listeners and the connection plane every
// stream transport shares (stream.go) over real loopback sockets. Timing
// bounds are shortened through Server.streamLim, which the harness sets
// before Run.

// streamOpts picks the listeners and bounds of a stream harness.
type streamOpts struct {
	tcp, tls, ws bool
	// tcpOnPrivatePort puts the tcp listener on the same port NUMBER as the
	// proxy's private UDP socket, which is where "SIP port 5060 over TCP"
	// sits in a real deployment.
	tcpOnPrivatePort bool
	// carrierSources is edge.carrier_sources ("" leaves INVITE admission
	// strict: only a live registration may call).
	carrierSources string
	tune           func(*streamLimits)
}

// startStreamHarness is startHarnessFull with tcp/tls listeners.
func startStreamHarness(t *testing.T, o streamOpts) *harness {
	t.Helper()
	pubUDP := freePort(t)
	priv := freePort(t)
	up := freePort(t)
	pubWS := 0
	if o.ws {
		pubWS = freeTCPPort(t)
	}
	var extra []string
	if o.tcp {
		p := freeTCPPort(t)
		if o.tcpOnPrivatePort {
			p = priv
		}
		extra = append(extra, fmt.Sprintf("tcp: %d", p))
	}
	if o.tls {
		extra = append(extra, fmt.Sprintf("tls: %d", freeTCPPort(t)))
	}
	mediaBase := nextMediaBase(t)
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, pubWS, 0, mediaBase, o.carrierSources, extra...)
	h := newHarness(t, yaml, priv)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	if o.tune != nil {
		o.tune(&h.srv.streamLim)
	}
	h.run()
	return h
}

// streamAddr returns the public address of a stream transport.
func (h *harness) streamAddr(transport string) string {
	switch transport {
	case "tcp":
		return h.publicTCP
	case "tls":
		return h.publicTLS
	case "ws":
		return h.publicWS
	}
	h.t.Fatalf("no stream transport %q", transport)
	return ""
}

func newStreamClient(t *testing.T, transport string) *client {
	t.Helper()
	if transport == "tls" {
		return newTLSClient(t)
	}
	return newTCPClient(t)
}

// binding returns the one live binding of an AoR.
func (h *harness) binding(aor string) (Binding, bool) {
	bs := h.srv.loc.ByAOR(aor)
	if len(bs) != 1 {
		return Binding{}, false
	}
	return bs[0], true
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// rawConn is a hand-written SIP stream client.
type rawConn struct {
	net.Conn
	br *bufio.Reader
}

// dialRaw opens a TCP connection to addr, and for tls completes a handshake
// that trusts the self-signed test certificate.
func dialRaw(t *testing.T, transport, addr string) *rawConn {
	t.Helper()
	return dialRawHandshake(t, transport, addr, true)
}

// dialRawHandshake is dialRaw, with the tls handshake optional: a connection
// the proxy is going to refuse never completes one.
func dialRawHandshake(t *testing.T, transport, addr string, handshake bool) *rawConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	if transport == "tls" && handshake {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test
		if err := tc.Handshake(); err != nil {
			_ = c.Close()
			t.Fatalf("tls handshake: %v", err)
		}
		c = tc
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawConn{Conn: c, br: bufio.NewReader(c)}
}

// optionsMsg is a complete OPTIONS request with a body of bodyLen bytes.
func optionsMsg(transport string, n, bodyLen int) string {
	body := strings.Repeat("x", bodyLen)
	return fmt.Sprintf("OPTIONS sip:127.0.0.1 SIP/2.0\r\n"+
		"Via: SIP/2.0/%s 127.0.0.1;branch=z9hG4bK-raw%d\r\n"+
		"Max-Forwards: 70\r\n"+
		"From: <sip:probe@example.com>;tag=t%d\r\n"+
		"To: <sip:127.0.0.1>\r\n"+
		"Call-ID: raw-%d-%d\r\n"+
		"CSeq: 1 OPTIONS\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		strings.ToUpper(transport), n, n, n, time.Now().UnixNano(), bodyLen, body)
}

// readStatus reads one response and returns its status line, or the read
// error (a closed connection is io.EOF).
func (c *rawConn) readStatus(d time.Duration) (string, error) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	status, err := c.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	clen := 0
	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "content-length") {
			clen, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if clen > 0 {
		if _, err := io.CopyN(io.Discard, c.br, int64(clen)); err != nil {
			return "", err
		}
	}
	return strings.TrimSpace(status), nil
}

// expectClosed fails unless the connection is closed by the proxy within d.
func (c *rawConn) expectClosed(t *testing.T, d time.Duration, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	if _, err := c.br.ReadByte(); err == nil {
		t.Fatalf("%s: the proxy answered instead of closing", what)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s: the connection is still open after %v", what, d)
	}
}

// expectOpenAndServing sends an OPTIONS and expects a 200.
func (c *rawConn) expectServing(t *testing.T, transport string, n int) {
	t.Helper()
	if _, err := io.WriteString(c, optionsMsg(transport, n, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := c.readStatus(3 * time.Second)
	if err != nil || !strings.Contains(st, "200") {
		t.Fatalf("OPTIONS: status %q err %v, want 200", st, err)
	}
}

// ---------------------------------------------------------------------
// Registration, calls, flows
// ---------------------------------------------------------------------

var streamTransportsUnderTest = []string{"tcp", "tls"}

// REGISTER, a call placed by the client, and its BYE, over one TCP or TLS
// connection. The switch sees UDP; the client's Via, Record-Route and
// Contact name the leg transport.
func TestStreamRegisterCallAndBye(t *testing.T) {
	for _, tr := range streamTransportsUnderTest {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			dest := h.streamAddr(tr)
			phone := newStreamClient(t, tr)

			if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), dest); res.StatusCode != 200 {
				t.Fatalf("REGISTER: %d", res.StatusCode)
			}
			b, ok := h.binding("1001@example.com")
			if !ok || b.Transport != tr {
				t.Fatalf("binding = %+v ok=%v, want one over %s", b, ok, tr)
			}

			invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30301))
			res := phone.do(t, invite, dest)
			if res.StatusCode != 200 {
				t.Fatalf("INVITE: %d", res.StatusCode)
			}
			// The public Record-Route (the one facing the caller is the
			// bottom value) and the Contact name this leg's transport.
			rrs := res.GetHeaders("Record-Route")
			if len(rrs) < 2 {
				t.Fatalf("Record-Route count = %d, want the double RR", len(rrs))
			}
			bottom := rrs[len(rrs)-1].(*sip.RecordRouteHeader)
			if v, _ := bottom.Address.UriParams.Get("transport"); v != tr {
				t.Errorf("caller-facing Record-Route = %s, want transport=%s", bottom.Address.String(), tr)
			}
			if c, ok := res.Contact(), res.Contact() != nil; !ok || c.Address.UriParams == nil {
				t.Errorf("200 Contact = %v", c)
			} else if v, _ := c.Address.UriParams.Get("transport"); v != tr {
				t.Errorf("200 Contact = %s, want transport=%s", c.Address.String(), tr)
			}
			// The switch's leg is plain UDP.
			invites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
			if len(invites) != 1 || !strings.EqualFold(invites[0].Via().Transport, "UDP") {
				t.Fatalf("the switch saw %v, want one INVITE over UDP", invites)
			}

			sendAck(t, phone, invite, res, dest)
			if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
				t.Errorf("the switch saw %d ACKs", len(acks))
			}
			bye := buildBye(phone, invite, res)
			if r := phone.do(t, bye, dest); r.StatusCode != 200 {
				t.Errorf("BYE: %d", r.StatusCode)
			}
			if byes := h.fs.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
				t.Errorf("the switch saw %d BYEs", len(byes))
			}
			waitForRelease(t, h)
		})
	}
}

// A call placed TO a registered TCP/TLS client travels over the connection
// the client registered on. The client's Contact is unreachable, so this
// proves the request used the flow; the Via and the Request-URI name the
// leg transport.
func TestStreamCallToRegisteredClient(t *testing.T) {
	for _, tr := range streamTransportsUnderTest {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			dest := h.streamAddr(tr)
			phone := newStreamClient(t, tr)
			if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), dest); res.StatusCode != 200 {
				t.Fatalf("REGISTER: %d", res.StatusCode)
			}
			stored := h.fs.contacts()
			if len(stored) == 0 {
				t.Fatal("nothing registered upstream")
			}
			// The switch is told FreeSBC's own private contact, over UDP.
			if !strings.Contains(stored[0], "transport=udp") {
				t.Errorf("registered contact %q, want transport=udp", stored[0])
			}

			phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
				if req.Method != sip.INVITE {
					_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
					return
				}
				res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(30311)))
				res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
				res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
				res.To().Params.Add("tag", sip.GenerateTagN(12))
				_ = tx.Respond(res)
			})
			var ruri sip.Uri
			if err := sip.ParseUri(stored[0], &ruri); err != nil {
				t.Fatal(err)
			}
			res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
			if res.StatusCode != 200 {
				t.Fatalf("inbound INVITE: %d", res.StatusCode)
			}
			select {
			case got := <-phone.inbound:
				if got.Method != sip.INVITE {
					t.Fatalf("the phone received %s", got.Method)
				}
				if v := got.Via(); v == nil || !strings.EqualFold(v.Transport, tr) {
					t.Errorf("the phone saw Via %v, want SIP/2.0/%s", v, strings.ToUpper(tr))
				}
				if v, _ := got.Recipient.UriParams.Get("transport"); v != tr {
					t.Errorf("Request-URI = %s, want transport=%s", got.Recipient.String(), tr)
				}
				rrs := got.GetHeaders("Record-Route")
				if len(rrs) == 0 {
					t.Fatal("no Record-Route toward the phone")
				}
				top := rrs[0].(*sip.RecordRouteHeader)
				if v, _ := top.Address.UriParams.Get("transport"); v != tr {
					t.Errorf("top Record-Route = %s, want transport=%s", top.Address.String(), tr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the phone never received the INVITE over its connection")
			}
			// Hang up from the switch: the BYE also uses the connection.
			if r := h.fs.uacBye(t, res); r.StatusCode != 200 {
				t.Errorf("BYE from the switch: %d", r.StatusCode)
			}
			waitForRelease(t, h)
		})
	}
}

// FreeSBC never dials a client. A binding whose connection is gone (here a
// binding planted with no connection behind it) fails the call with 480, and
// the address in it, which is listening, never sees a connection attempt.
func TestStreamNeverDialsClient(t *testing.T) {
	for _, tr := range streamTransportsUnderTest {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			trap, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer trap.Close()
			dialed := make(chan struct{}, 4)
			go func() {
				for {
					c, err := trap.Accept()
					if err != nil {
						return
					}
					dialed <- struct{}{}
					_ = c.Close()
				}
			}()
			src := netip.MustParseAddrPort(trap.Addr().String())
			b, err := h.srv.loc.Put(Binding{AOR: "1001@example.com", User: "1001", Transport: tr, Source: src,
				CallID: "planted", ExpiresAt: time.Now().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			ruri := sip.Uri{User: "1001", Host: "127.0.0.1", Port: portOf(h.privateSIP), UriParams: sip.NewParams()}
			ruri.UriParams.Add(contactTokenParam, b.Token)
			res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
			if res.StatusCode != 480 {
				t.Fatalf("INVITE to a client with no connection: %d, want 480", res.StatusCode)
			}
			select {
			case <-dialed:
				t.Fatal("FreeSBC dialed the client's registered address")
			case <-time.After(500 * time.Millisecond):
			}
			waitForRelease(t, h)
		})
	}
}

// A dropped connection removes the binding made over it.
func TestStreamCloseDropsBindings(t *testing.T) {
	for _, tr := range streamTransportsUnderTest {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			phone := newStreamClient(t, tr)
			if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.streamAddr(tr)); res.StatusCode != 200 {
				t.Fatalf("REGISTER: %d", res.StatusCode)
			}
			if h.srv.loc.Count() != 1 || h.srv.streams.open() != 1 {
				t.Fatalf("bindings %d, connections %d, want 1 and 1", h.srv.loc.Count(), h.srv.streams.open())
			}
			phone.cancel()
			waitFor(t, 5*time.Second, "the binding to go with the connection", func() bool { return h.srv.loc.Count() == 0 })
			waitFor(t, 5*time.Second, "the connection slot to be released", func() bool { return h.srv.streams.open() == 0 })
			if g := h.srv.metrics.Snapshot().StreamConnections[tr]; g != 0 {
				t.Errorf("open-connection gauge for %s = %d after close", tr, g)
			}
		})
	}
}

// The same device registering again over a NEW connection (same AoR and
// Call-ID) replaces the binding, and the old connection closing afterwards
// does not take the new binding with it.
func TestStreamReRegisterOnNewConnectionReplacesBinding(t *testing.T) {
	for _, tr := range streamTransportsUnderTest {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			dest := h.streamAddr(tr)
			old := newStreamClient(t, tr)
			if res := old.do(t, old.buildRegister("1001", "example.com", 600, ""), dest); res.StatusCode != 200 {
				t.Fatalf("REGISTER: %d", res.StatusCode)
			}
			first, ok := h.binding("1001@example.com")
			if !ok {
				t.Fatal("no binding after the first REGISTER")
			}

			fresh := newStreamClient(t, tr)
			if res := fresh.do(t, fresh.buildRegister("1001", "example.com", 600, ""), dest); res.StatusCode != 200 {
				t.Fatalf("second REGISTER: %d", res.StatusCode)
			}
			second, ok := h.binding("1001@example.com")
			if !ok {
				t.Fatalf("bindings after the second REGISTER = %d, want 1", len(h.srv.loc.ByAOR("1001@example.com")))
			}
			if second.Source == first.Source {
				t.Fatalf("binding still on the old connection %v", second.Source)
			}
			if second.Token != first.Token {
				t.Errorf("token changed across the move: the switch holds %s", first.Token)
			}

			old.cancel()
			waitFor(t, 5*time.Second, "the old connection to close", func() bool { return h.srv.streams.open() == 1 })
			if b, ok := h.binding("1001@example.com"); !ok || b.Source != second.Source {
				t.Errorf("binding after the old connection closed = %+v ok=%v, want it kept on %v", b, ok, second.Source)
			}
		})
	}
}

// ---------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------

// A TCP listener on the same port NUMBER as the private UDP socket is still
// public: a connection to it that forges X-FreeSBC-Arrival, from the
// switch's own IP, is not the switch.
func TestStreamTCPOnPrivatePortNeverGetsPrivateTrust(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true, tcpOnPrivatePort: true})
	if portOf(h.publicTCP) != portOf(h.privateSIP) {
		t.Fatalf("tcp %s is not on the private port %s", h.publicTCP, h.privateSIP)
	}

	// The filter, asked directly with the private socket as the local
	// address: nothing is stamped on a TCP read.
	filter := h.srv.readFilter()
	req := []byte(optionsMsg("tcp", 1, 0))
	out, err := filter(sip.TransportReadProps{
		Transport:  "TCP",
		LocalAddr:  net.TCPAddrFromAddrPort(h.srv.privAddr),
		RemoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000},
	}, req)
	if err != nil || !bytes.Equal(out, req) {
		t.Fatalf("a TCP read on the private port was altered or dropped: err=%v\n%s", err, out)
	}

	// On the wire: an out-of-dialog INVITE with a forged marker. As the
	// switch it would be classified by Request-URI and get a 404; as the
	// public stranger it is, it is dropped without a word.
	c := dialRaw(t, "tcp", h.publicTCP)
	forged := fmt.Sprintf("INVITE sip:1001@127.0.0.1:%d;%s=nosuchtoken SIP/2.0\r\n"+
		"%s: 0123456789abcdef0123456789abcdef;private\r\n"+
		"Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-forged\r\n"+
		"Max-Forwards: 70\r\nFrom: <sip:3003@example.com>;tag=f1\r\nTo: <sip:1001@example.com>\r\n"+
		"Call-ID: forged-1\r\nCSeq: 1 INVITE\r\nContact: <sip:3003@127.0.0.1>\r\nContent-Length: 0\r\n\r\n",
		portOf(h.privateSIP), contactTokenParam, arrivalHeader)
	if _, err := io.WriteString(c, forged); err != nil {
		t.Fatal(err)
	}
	if st, err := c.readStatus(700 * time.Millisecond); err == nil {
		t.Fatalf("a forged-marker INVITE over TCP was answered %q: it was treated as the switch", st)
	}
	waitFor(t, 3*time.Second, "the INVITE to be counted as not admitted", func() bool {
		return h.srv.metrics.Snapshot().AdmissionDrops["invite_not_admitted"] == 1
	})
	if n := h.srv.dialogs.sessionCount(); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
}

// ---------------------------------------------------------------------
// Keep-alive and framing
// ---------------------------------------------------------------------

// The RFC 5626 double-CRLF ping is answered with a single CRLF, counts as no
// parse failure, and leaves the connection serving.
func TestStreamCRLFKeepAlive(t *testing.T) {
	for _, tr := range streamTransportsUnderTest {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			c := dialRaw(t, tr, h.streamAddr(tr))
			for i := 0; i < 3; i++ {
				if _, err := io.WriteString(c, "\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				pong := make([]byte, 2)
				if _, err := io.ReadFull(c.br, pong); err != nil || string(pong) != "\r\n" {
					t.Fatalf("pong = %q err %v, want CRLF", pong, err)
				}
			}
			c.expectServing(t, tr, 1)
			for tname, n := range h.srv.metrics.Snapshot().ParseFailures {
				if n != 0 {
					t.Errorf("parse failures on %s = %d after keep-alives", tname, n)
				}
			}
		})
	}
}

// A message split over several reads, and several messages in one read, are
// both handled: the read path neither drops nor mangles a fragment.
func TestStreamSplitAndCoalescedMessages(t *testing.T) {
	for _, tr := range streamTransportsUnderTest {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			c := dialRaw(t, tr, h.streamAddr(tr))

			// One request, with a body, in four writes cut in the start
			// line, the headers, the blank line and the body.
			msg := optionsMsg(tr, 1, 600)
			cuts := []int{7, strings.Index(msg, "Call-ID") + 3, strings.Index(msg, "\r\n\r\n") + 2, len(msg) - 100, len(msg)}
			prev := 0
			for _, cut := range cuts {
				if _, err := io.WriteString(c, msg[prev:cut]); err != nil {
					t.Fatal(err)
				}
				prev = cut
				time.Sleep(40 * time.Millisecond)
			}
			if st, err := c.readStatus(3 * time.Second); err != nil || !strings.Contains(st, "200") {
				t.Fatalf("split request: status %q err %v", st, err)
			}

			// Three requests in one write, with a keep-alive between.
			batch := optionsMsg(tr, 2, 0) + "\r\n\r\n" + optionsMsg(tr, 3, 50) + optionsMsg(tr, 4, 0)
			if _, err := io.WriteString(c, batch); err != nil {
				t.Fatal(err)
			}
			got := 0
			for got < 3 {
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				b, err := c.br.Peek(2)
				if err != nil {
					t.Fatalf("after %d responses: %v", got, err)
				}
				if string(b) == "\r\n" { // the keep-alive's pong
					_, _ = c.br.Discard(2)
					continue
				}
				if st, err := c.readStatus(3 * time.Second); err != nil || !strings.Contains(st, "200") {
					t.Fatalf("coalesced request %d: status %q err %v", got, st, err)
				}
				got++
			}
		})
	}
}

// A message larger than a datagram's cap but within the message bound is
// served (a stream read is not capped), and one over the bound closes the
// connection. A header block that never ends does the same.
func TestStreamOversizedMessageRefused(t *testing.T) {
	for _, tr := range streamTransportsUnderTest {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			limit := h.srv.streamLim.maxMessage

			c := dialRaw(t, tr, h.streamAddr(tr))
			if _, err := io.WriteString(c, optionsMsg(tr, 1, limit-1024)); err != nil {
				t.Fatal(err)
			}
			if st, err := c.readStatus(3 * time.Second); err != nil || !strings.Contains(st, "200") {
				t.Fatalf("message just under the bound: status %q err %v", st, err)
			}

			// Declared too large: refused before the body is read.
			if _, err := io.WriteString(c, strings.Replace(optionsMsg(tr, 2, 0), "Content-Length: 0", fmt.Sprintf("Content-Length: %d", limit), 1)); err != nil {
				t.Fatal(err)
			}
			c.expectClosed(t, 3*time.Second, "declared oversize")
			waitFor(t, 3*time.Second, "the oversize close to be counted", func() bool {
				return h.srv.metrics.Snapshot().StreamClosed["oversize"] == 1
			})

			// No end to the headers.
			c2 := dialRaw(t, tr, h.streamAddr(tr))
			go func() {
				_, _ = io.WriteString(c2, "OPTIONS sip:x SIP/2.0\r\n"+strings.Repeat("X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n", limit/30))
			}()
			c2.expectClosed(t, 3*time.Second, "endless header block")
			if n := h.srv.metrics.Snapshot().StreamClosed["oversize"]; n != 2 {
				t.Errorf("oversize closes = %d, want 2", n)
			}
		})
	}
}

// ---------------------------------------------------------------------
// Caps, timeouts, shield
// ---------------------------------------------------------------------

// The per-source and global connection caps refuse the connection over them,
// on every stream transport, and free a slot when a connection closes.
func TestStreamConnectionCaps(t *testing.T) {
	for _, tr := range []string{"tcp", "tls", "ws"} {
		t.Run(tr+"/per-ip", func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true, ws: true,
				tune: func(l *streamLimits) { l.maxPerIP = 3 }})
			var conns []*rawConn
			for i := 0; i < 3; i++ {
				conns = append(conns, dialRaw(t, tr, h.streamAddr(tr)))
			}
			waitFor(t, 3*time.Second, "three connections", func() bool { return h.srv.streams.open() == 3 })
			over := dialRawHandshake(t, tr, h.streamAddr(tr), false)
			over.expectClosed(t, 3*time.Second, "the connection over the per-source cap")
			if n := h.srv.metrics.Snapshot().StreamRefused["ip_cap"]; n != 1 {
				t.Errorf("ip_cap refusals = %d, want 1", n)
			}
			// A freed slot is usable again.
			_ = conns[0].Close()
			waitFor(t, 3*time.Second, "a slot to free", func() bool { return h.srv.streams.open() == 2 })
			dialRaw(t, tr, h.streamAddr(tr))
			waitFor(t, 3*time.Second, "the new connection to be admitted", func() bool { return h.srv.streams.open() == 3 })
		})
	}
	t.Run("global", func(t *testing.T) {
		h := startStreamHarness(t, streamOpts{tcp: true, tls: true,
			tune: func(l *streamLimits) { l.maxTotal = 2 }})
		dialRaw(t, "tcp", h.publicTCP)
		dialRaw(t, "tls", h.publicTLS)
		waitFor(t, 3*time.Second, "two connections", func() bool { return h.srv.streams.open() == 2 })
		over := dialRawHandshake(t, "tcp", h.publicTCP, false)
		over.expectClosed(t, 3*time.Second, "the connection over the global cap")
		if n := h.srv.metrics.Snapshot().StreamRefused["global_cap"]; n != 1 {
			t.Errorf("global_cap refusals = %d, want 1", n)
		}
	})
}

// A connection carrying nothing is closed after the idle timeout; one with a
// live registration binding is not, and goes when the binding does.
func TestStreamIdleTimeout(t *testing.T) {
	tune := func(l *streamLimits) { l.idle = 250 * time.Millisecond }
	t.Run("unbound", func(t *testing.T) {
		h := startStreamHarness(t, streamOpts{tcp: true, tune: tune})
		c := dialRaw(t, "tcp", h.publicTCP)
		c.expectClosed(t, 3*time.Second, "a silent unregistered connection")
		if n := h.srv.metrics.Snapshot().StreamClosed["idle"]; n != 1 {
			t.Errorf("idle closes = %d, want 1", n)
		}
	})
	t.Run("registered", func(t *testing.T) {
		h := startStreamHarness(t, streamOpts{tcp: true, tune: tune})
		phone := newTCPClient(t)
		dest := h.publicTCP
		if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), dest); res.StatusCode != 200 {
			t.Fatalf("REGISTER: %d", res.StatusCode)
		}
		time.Sleep(4 * h.srv.streamLim.idle)
		if h.srv.streams.open() != 1 || h.srv.loc.Count() != 1 {
			t.Fatalf("a registered connection was closed for being quiet: %d connections, %d bindings",
				h.srv.streams.open(), h.srv.loc.Count())
		}
		// And it still works.
		if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), dest); res.StatusCode != 200 {
			t.Fatalf("refresh after the quiet period: %d", res.StatusCode)
		}
		// Un-registering makes it idle like any other.
		if res := phone.do(t, phone.buildRegister("1001", "example.com", 0, ""), dest); res.StatusCode != 200 {
			t.Fatalf("un-REGISTER: %d", res.StatusCode)
		}
		waitFor(t, 3*time.Second, "the idle connection to close", func() bool { return h.srv.streams.open() == 0 })
	})
	t.Run("carrier source", func(t *testing.T) {
		h := startStreamHarness(t, streamOpts{tcp: true, tune: tune, carrierSources: harnessCarrierSources})
		c := dialRaw(t, "tcp", h.publicTCP)
		time.Sleep(4 * h.srv.streamLim.idle)
		c.expectServing(t, "tcp", 1)
	})
}

// A message that has started must complete within the message timeout, even
// when bytes keep trickling in.
func TestStreamSlowLorisClosed(t *testing.T) {
	for _, tr := range []string{"tcp", "tls", "ws"} {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true, ws: true,
				tune: func(l *streamLimits) { l.message = 400 * time.Millisecond; l.handshake = 400 * time.Millisecond }})
			c := dialRaw(t, tr, h.streamAddr(tr))
			start := "OPTIONS sip:127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-slow\r\n"
			if tr == "ws" {
				start = "GET / HTTP/1.1\r\nHost: x\r\n" // a request that never ends
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if _, err := io.WriteString(c, start); err != nil {
					return
				}
				for i := 0; i < 100; i++ { // one header byte every 50 ms
					time.Sleep(50 * time.Millisecond)
					if _, err := io.WriteString(c, "X"); err != nil {
						return
					}
				}
			}()
			begin := time.Now()
			c.expectClosed(t, 4*time.Second, "a trickled message")
			if took := time.Since(begin); took > 3*time.Second {
				t.Errorf("the slow client held the connection for %v", took)
			}
			c.Close()
			<-done
			snap := h.srv.metrics.Snapshot().StreamClosed
			if snap["slow"]+snap["handshake"] != 1 {
				t.Errorf("slow/handshake closes = %v, want one", snap)
			}
		})
	}
}

// requireFlow takes a reference on the pooled connection to look it up and
// hands it back: the count is what it was, so the lookup never makes sipgo
// close, or keep open, a connection it would not have.
func TestRequireFlowLeavesConnectionRefsAlone(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true})
	phone := newTCPClient(t)
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicTCP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	b, _ := h.binding("1001@example.com")
	refs := func() int {
		c, err := h.srv.srv.TransportLayer().GetConnection("tcp", b.Source.String())
		if err != nil {
			t.Fatalf("no pooled connection: %v", err)
		}
		n := c.Ref(0)
		_, _ = c.TryClose()
		return n
	}
	before := refs()
	req := sip.NewRequest(sip.OPTIONS, sip.Uri{Host: "x"})
	req.SetTransport("TCP")
	req.SetDestination(b.Source.String())
	for i := 0; i < 5; i++ {
		if err := h.srv.requireFlow(req); err != nil {
			t.Fatalf("requireFlow: %v", err)
		}
	}
	if after := refs(); after != before {
		t.Errorf("connection refcount %d -> %d across requireFlow", before, after)
	}
	req.SetDestination("127.0.0.1:1")
	if err := h.srv.requireFlow(req); err != errNoFlow {
		t.Errorf("requireFlow with no connection = %v, want errNoFlow", err)
	}
	req.SetTransport("UDP")
	if err := h.srv.requireFlow(req); err != nil {
		t.Errorf("requireFlow on UDP = %v, want nil", err)
	}
}

// A client that never completes the TLS handshake, or the WebSocket upgrade
// request, is cut at the handshake timeout, and does not hold the listener.
func TestStreamHandshakeTimeout(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true, tls: true, ws: true,
		tune: func(l *streamLimits) { l.handshake = 300 * time.Millisecond }})
	for _, tr := range []string{"tls", "ws"} {
		raw, err := net.Dial("tcp", h.streamAddr(tr))
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		c := &rawConn{Conn: raw, br: bufio.NewReader(raw)}
		c.expectClosed(t, 3*time.Second, tr+" client that sent nothing")
	}
	// The listeners are still serving others.
	dialRaw(t, "tls", h.publicTLS).expectServing(t, "tls", 1)
	if n := h.srv.metrics.Snapshot().StreamClosed["handshake"]; n != 2 {
		t.Errorf("handshake closes = %d, want 2", n)
	}
}

// New connections cost the source's rate token, so a flood of them (each a
// TLS handshake on tls) is refused once the budget is gone.
func TestStreamConnectionRate(t *testing.T) {
	for _, tr := range []string{"tcp", "tls"} {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
			auditReplaceConfig(h, func(c *config.Config) { c.Shield.RateLimit = "3/h per_ip" })
			for i := 0; i < 8; i++ {
				raw, err := net.Dial("tcp", h.streamAddr(tr))
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
			}
			waitFor(t, 3*time.Second, "refusals for rate", func() bool {
				return h.srv.metrics.Snapshot().StreamRefused["rate"] >= 5
			})
		})
	}
}

// A banned source's stream is closed on the request that earned the ban, and
// its next connection is refused at accept.
func TestStreamBannedSource(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true})
	c := dialRaw(t, "tcp", h.publicTCP)
	msg := strings.Replace(optionsMsg("tcp", 1, 0), "CSeq: 1 OPTIONS\r\n", "CSeq: 1 OPTIONS\r\nUser-Agent: friendly-scanner\r\n", 1)
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	c.expectClosed(t, 3*time.Second, "a scanner's connection")
	again := dialRaw(t, "tcp", h.publicTCP)
	again.expectClosed(t, 3*time.Second, "a banned source's new connection")
	if n := h.srv.metrics.Snapshot().StreamRefused["banned"]; n != 1 {
		t.Errorf("banned refusals = %d, want 1", n)
	}
}

// The stream metrics are exported from zero.
func TestStreamMetricsFromZero(t *testing.T) {
	snap := NewMetrics().Snapshot()
	for _, tr := range streamTransports {
		if _, ok := snap.StreamConnections[tr]; !ok {
			t.Errorf("no connection gauge for %s", tr)
		}
	}
	for _, l := range streamRefusalLabels {
		if _, ok := snap.StreamRefused[l]; !ok {
			t.Errorf("no refusal counter for %q", l)
		}
	}
	for _, l := range streamCloseLabels[1:] {
		if _, ok := snap.StreamClosed[l]; !ok {
			t.Errorf("no close counter for %q", l)
		}
	}
}

// ---------------------------------------------------------------------
// Framers
// ---------------------------------------------------------------------

func TestSIPFramer(t *testing.T) {
	msg := func(clen int, body string) string {
		return "INVITE sip:a SIP/2.0\r\nCall-ID: x\r\nContent-Length: " + strconv.Itoa(clen) + "\r\n\r\n" + body
	}
	t.Run("split everywhere", func(t *testing.T) {
		m := msg(5, "hello")
		for cut := 1; cut < len(m); cut++ {
			f := &sipFramer{max: 4096}
			c1, bad1 := f.feed([]byte(m[:cut]))
			if bad1 != closeNone || !f.partial() {
				t.Fatalf("cut %d: first part bad=%v partial=%v", cut, bad1, f.partial())
			}
			c2, bad2 := f.feed([]byte(m[cut:]))
			if bad2 != closeNone || f.partial() || c1+c2 != 1 {
				t.Fatalf("cut %d: bad=%v partial=%v charges=%d", cut, bad2, f.partial(), c1+c2)
			}
		}
	})
	t.Run("coalesced and keep-alive", func(t *testing.T) {
		f := &sipFramer{max: 4096}
		c, bad := f.feed([]byte(msg(0, "") + "\r\n\r\n" + msg(3, "abc") + msg(0, "")))
		if bad != closeNone || c != 3 || f.partial() {
			t.Fatalf("charges=%d bad=%v partial=%v, want 3 messages", c, bad, f.partial())
		}
		if c, _ := f.feed([]byte("\r\n\r\n")); c != 1 {
			t.Errorf("a bare keep-alive costs %d tokens, want 1", c)
		}
	})
	t.Run("compact content length", func(t *testing.T) {
		f := &sipFramer{max: 4096}
		c, bad := f.feed([]byte("BYE sip:a SIP/2.0\r\nl: 2\r\n\r\nhiBYE sip:a SIP/2.0\r\nl: 0\r\n\r\n"))
		if bad != closeNone || c != 2 || f.partial() {
			t.Fatalf("charges=%d bad=%v partial=%v", c, bad, f.partial())
		}
	})
	for name, tc := range map[string]struct {
		in   string
		want streamClose
	}{
		"declared too large": {msg(5000, ""), closeOversize},
		"bad length":         {"X sip:a SIP/2.0\r\nContent-Length: abc\r\n\r\n", closeMalformed},
		"negative length":    {"X sip:a SIP/2.0\r\nContent-Length: -1\r\n\r\n", closeMalformed},
		"conflicting length": {"X sip:a SIP/2.0\r\nContent-Length: 1\r\nl: 2\r\n\r\n", closeMalformed},
		"endless headers":    {"X sip:a SIP/2.0\r\n" + strings.Repeat("A: b\r\n", 2000), closeOversize},
	} {
		t.Run(name, func(t *testing.T) {
			f := &sipFramer{max: 4096}
			if _, bad := f.feed([]byte(tc.in)); bad != tc.want {
				t.Errorf("bad = %v, want %v", bad, tc.want)
			}
		})
	}
}

func TestWSFramer(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n"
	frame := func(payload int, mask bool, ext int) []byte {
		b := []byte{0x81, 0}
		switch ext {
		case 2:
			b[1] = 126
			b = append(b, byte(payload>>8), byte(payload))
		case 8:
			b[1] = 127
			b = append(b, 0, 0, 0, 0, 0, 0, byte(payload>>8), byte(payload))
		default:
			b[1] = byte(payload)
		}
		if mask {
			b[1] |= 0x80
			b = append(b, 1, 2, 3, 4)
		}
		return append(b, make([]byte, payload)...)
	}
	stream := append([]byte(req), frame(10, true, 0)...)
	stream = append(stream, frame(300, true, 2)...)
	stream = append(stream, frame(70, true, 8)...)
	stream = append(stream, frame(0, true, 0)...)
	for step := 1; step <= 7; step++ { // every chunking ends at a message boundary
		f := &wsFramer{max: 4096}
		for i := 0; i < len(stream); i += step {
			if _, bad := f.feed(stream[i:min(i+step, len(stream))]); bad != closeNone {
				t.Fatalf("step %d at %d: bad %v", step, i, bad)
			}
		}
		if f.partial() {
			t.Errorf("step %d: still partial at the end of whole frames", step)
		}
	}
	f := &wsFramer{max: 100}
	f.feed([]byte(req))
	if _, bad := f.feed(frame(300, true, 2)[:8]); bad != closeOversize {
		t.Errorf("a 300-byte frame under a 100-byte bound: bad = %v", bad)
	}
	f = &wsFramer{max: 4096}
	f.feed([]byte(req))
	f.feed(frame(10, true, 0)[:5])
	if !f.partial() {
		t.Error("a frame cut in its payload is not partial")
	}
}

// FuzzStreamFramer feeds arbitrary bytes to both framers. They must never
// panic, and where a stream is closed for must not depend on how its bytes
// were cut into reads.
func FuzzStreamFramer(f *testing.F) {
	f.Add([]byte("OPTIONS sip:x SIP/2.0\r\nContent-Length: 3\r\n\r\nabc\r\n\r\n"), 5)
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n\x81\x85\x01\x02\x03\x04hello"), 9)
	f.Add([]byte("X sip:a SIP/2.0\r\nl: 999999\r\n\r\n"), 1)
	f.Fuzz(func(t *testing.T, data []byte, cut int) {
		if cut < 1 {
			cut = 1
		}
		for name, mk := range map[string]func() framer{
			"sip": func() framer { return &sipFramer{max: 2048} },
			"ws":  func() framer { return &wsFramer{max: 2048} },
		} {
			whole := mk()
			_, badWhole := whole.feed(data)
			chunked := mk()
			var badChunked streamClose
			for i := 0; i < len(data) && badChunked == closeNone; i += cut {
				_, badChunked = chunked.feed(data[i:min(i+cut, len(data))])
			}
			if (badWhole == closeNone) != (badChunked == closeNone) {
				t.Fatalf("%s: whole -> %v, cut every %d -> %v", name, badWhole, cut, badChunked)
			}
			if badWhole == closeNone && whole.partial() != chunked.partial() {
				t.Fatalf("%s: partial differs between whole and cut reads", name)
			}
		}
	})
}

func TestStreamKeyGroupsIPv6By64(t *testing.T) {
	a := streamKey(netip.MustParseAddr("2001:db8:1:2::1"))
	b := streamKey(netip.MustParseAddr("2001:db8:1:2:ffff::9"))
	c := streamKey(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Errorf("keys %v %v %v: the same /64 must group, another must not", a, b, c)
	}
	if k := streamKey(netip.MustParseAddr("::ffff:10.0.0.1")); k != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("4in6 key = %v", k)
	}
}
