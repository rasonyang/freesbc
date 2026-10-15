package edge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// A provisional response the switch sends right before its final must reach
// the caller before that final (issue #213): sipgo hands each response to
// the client transaction on its own goroutine, so the 200 can win and the
// transaction then drops the 180 (prov.go). The caller here is a raw socket,
// because a sipgo client phone has the same race on its own side.
//
// Timing-based over real loopback sockets: re-run once before treating a
// flake as failure.

// provSwitchHook answers with a provisional (180, or 183 carrying the
// answer's SDP) and the final back to back, on one To tag.
func provSwitchHook(h *harness, prov, final int) func(*sip.Request, sip.ServerTransaction) bool {
	return func(req *sip.Request, tx sip.ServerTransaction) bool {
		tag := sip.GenerateTagN(12)
		mk := func(code int, reason string, withSDP bool) *sip.Response {
			if !withSDP {
				res := sip.NewResponseFromRequest(req, code, reason, nil)
				res.To().Params.Add("tag", tag)
				return res
			}
			body := []byte(h.fs.answerSDP(req))
			res := sip.NewResponseFromRequest(req, code, reason, body)
			res.To().Params.Add("tag", tag)
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
			return res
		}
		// 180 has no body; 183 carries the answer.
		_ = tx.Respond(mk(prov, map[int]string{180: "Ringing", 183: "Session Progress"}[prov], prov == 183))
		if final == 200 {
			_ = tx.Respond(mk(200, "OK", true))
		} else {
			_ = tx.Respond(mk(final, "Busy Here", false))
		}
		return true
	}
}

// rawSIP is a raw SIP endpoint over UDP or a stream connection.
type rawSIP struct {
	t    *testing.T
	udp  *net.UDPConn
	dest *net.UDPAddr
	conn *rawConn
}

func (r *rawSIP) send(req *sip.Request) {
	r.t.Helper()
	if req.ContentLength() == nil {
		// A stream parser waits for it; String() omits it on an empty body.
		cl := sip.ContentLengthHeader(0)
		req.AppendHeader(&cl)
	}
	var err error
	if r.udp != nil {
		_, err = r.udp.WriteToUDP([]byte(req.String()), r.dest)
	} else {
		_, err = io.WriteString(r.conn, req.String())
	}
	if err != nil {
		r.t.Fatalf("send %s: %v", req.Method, err)
	}
}

// read returns the next message as parsed from the wire.
func (r *rawSIP) read(d time.Duration) (*sip.Response, error) {
	var raw []byte
	if r.udp != nil {
		_ = r.udp.SetReadDeadline(time.Now().Add(d))
		buf := make([]byte, 4096)
		n, _, err := r.udp.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		raw = buf[:n]
	} else {
		var err error
		if raw, err = r.conn.readMessage(d); err != nil {
			return nil, err
		}
	}
	msg, err := sip.ParseMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", raw, err)
	}
	res, ok := msg.(*sip.Response)
	if !ok {
		return nil, fmt.Errorf("not a response: %.40q", raw)
	}
	return res, nil
}

// readMessage reads one whole message, body included.
func (c *rawConn) readMessage(d time.Duration) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	return readRawMessage(c.br)
}

func readRawMessage(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	clen := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		buf = append(buf, line...)
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "content-length") {
			clen, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	body := make([]byte, clen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	return append(buf, body...), nil
}

// provCall places a call from a raw caller and returns every response up to
// the final, in arrival order.
func provCall(t *testing.T, h *harness, transport string, prov, final int) (rs *rawSIP, invite *sip.Request, got []*sip.Response, phone *client) {
	t.Helper()
	h.fs.setInviteHook(provSwitchHook(h, prov, final))
	rs = &rawSIP{t: t}
	if transport == "udp" {
		phone = newUDPClient(t)
		rs.udp = auditUDP(t)
		rs.dest = auditLocalAddr(portOf(h.publicUDP))
	} else {
		phone = newStreamClient(t, transport)
		rs.conn = dialRaw(t, transport, h.streamAddr(transport))
	}
	invite = phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(auditUDPPort(auditUDP(t))))
	rs.send(invite)
	for {
		res, err := rs.read(5 * time.Second)
		if err != nil {
			t.Fatalf("waiting for the final response (got %d so far): %v", len(got), err)
		}
		if res.StatusCode == 100 {
			continue
		}
		got = append(got, res)
		if res.StatusCode >= 200 {
			return rs, invite, got, phone
		}
	}
}

func TestProvisionalBeforeFinal(t *testing.T) {
	cases := []struct{ name, transport string }{
		{"udp", "udp"}, {"tcp", "tcp"}, {"tls", "tls"},
	}
	for _, tc := range cases {
		for _, prov := range []int{180, 183} {
			t.Run(fmt.Sprintf("%s/%d-200", tc.name, prov), func(t *testing.T) {
				h := startStreamHarness(t, streamOpts{tcp: true, tls: true, carrierSources: harnessCarrierSources})
				rs, invite, got, phone := provCall(t, h, tc.transport, prov, 200)
				if len(got) != 2 || got[0].StatusCode != prov || got[1].StatusCode != 200 {
					t.Fatalf("responses = %v, want %d then 200", codes(got), prov)
				}
				if prov == 183 && !strings.Contains(string(got[0].Body()), "m=audio") {
					t.Errorf("183 carries no SDP: %q", got[0].Body())
				}
				ack := buildRawAck(phone, invite, got[1])
				rs.send(ack)
				h.fs.waitFor(sip.ACK, 1, 3*time.Second)
				rs.send(buildBye(phone, invite, got[1]))
				if r, err := rs.read(5 * time.Second); err != nil || r.StatusCode != 200 {
					t.Fatalf("BYE: %v %v", r, err)
				}
				h.fs.waitFor(sip.BYE, 1, 3*time.Second)
				waitForRelease(t, h)
			})
		}
	}
	t.Run("udp/180-486", func(t *testing.T) {
		h := startStreamHarness(t, streamOpts{tcp: true, carrierSources: harnessCarrierSources})
		_, _, got, _ := provCall(t, h, "udp", 180, 486)
		if len(got) != 2 || got[0].StatusCode != 180 || got[1].StatusCode != 486 {
			t.Fatalf("responses = %v, want 180 then 486", codes(got))
		}
		waitForRelease(t, h)
	})
}

func codes(rs []*sip.Response) []int {
	var c []int
	for _, r := range rs {
		c = append(c, r.StatusCode)
	}
	return c
}

// buildRawAck is the caller's end-to-end ACK for a 2xx.
func buildRawAck(c *client, invite *sip.Request, res *sip.Response) *sip.Request {
	ack := sip.NewRequest(sip.ACK, invite.Recipient)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0",
		Transport: strings.ToUpper(c.transport), Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	ack.PrependHeader(via)
	sip.CopyHeaders("From", invite, ack)
	sip.CopyHeaders("Call-ID", invite, ack)
	ack.AppendHeader(sip.HeaderClone(res.To()))
	ack.AppendHeader(&sip.CSeqHeader{SeqNo: invite.CSeq().SeqNo, MethodName: sip.ACK})
	mf := sip.MaxForwardsHeader(70)
	ack.AppendHeader(&mf)
	copyRouteFromRecordRoute(res, ack)
	return ack
}

// provTable records the *sip.Response the transport layer hands to
// OnMessage, and pumpInvite compares it by pointer with the ones read from
// Responses(). A sipgo upgrade that clones a response between the two must
// fail here, not silently relay a provisional twice.
func TestProvTableSeesTransactionResponsePointers(t *testing.T) {
	var tbl provTable
	phone := newUDPClient(t)
	phone.ua.TransportLayer().OnMessage(tbl.observe)
	far := auditUDP(t)

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(40000))
	invite.SetTransport("UDP")
	invite.SetDestination(far.LocalAddr().String())
	release := tbl.register(invite)
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := phone.cli.TransactionRequest(ctx, invite)
	if err != nil {
		t.Fatalf("send INVITE: %v", err)
	}
	defer tx.Terminate()

	buf := make([]byte, 4096)
	_ = far.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := far.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("far end read: %v", err)
	}
	msg, err := sip.ParseMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	req := msg.(*sip.Request)
	tag := sip.GenerateTagN(12)
	var want []*sip.Response
	for _, code := range []int{180, 200} {
		res := sip.NewResponseFromRequest(req, code, "x", nil)
		res.To().Params.Add("tag", tag)
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: 5060}})
		if _, err := far.WriteToUDP([]byte(res.String()), from); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	for len(want) < 2 {
		select {
		case r := <-tx.Responses():
			want = append(want, r)
		case <-ctx.Done():
			t.Fatalf("got %d responses", len(want))
		}
	}
	if want[0].StatusCode != 180 || want[1].StatusCode != 200 {
		t.Fatalf("responses = %v", codes(want))
	}
	got := tbl.before(invite, want[1], nil)
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("recorded provisionals = %v, want the pointer tx.Responses() returned", got)
	}
	if got := tbl.before(invite, want[1], map[*sip.Response]struct{}{want[0]: {}}); len(got) != 0 {
		t.Errorf("an already relayed provisional was returned again: %v", got)
	}
}

// A final the pump reads before observe has recorded it (the transaction
// layer's goroutine can win) still replays every recorded unseen
// provisional.
func TestProvBeforeUnrecordedFinal(t *testing.T) {
	var tbl provTable
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(40000))
	release := tbl.register(invite)
	defer release()
	mk := func(code int) *sip.Response {
		return sip.NewResponseFromRequest(invite, code, "x", nil)
	}
	r180, r183, final := mk(180), mk(183), mk(200)
	tbl.observe(r180)
	tbl.observe(r183)
	got := tbl.before(invite, final, map[*sip.Response]struct{}{r180: {}})
	if len(got) != 1 || got[0] != r183 {
		t.Fatalf("before = %v, want only the unseen 183", got)
	}
	if got := tbl.before(invite, final, nil); len(got) != 2 || got[0] != r180 || got[1] != r183 {
		t.Fatalf("before = %v, want 180 then 183 in order", got)
	}
}
