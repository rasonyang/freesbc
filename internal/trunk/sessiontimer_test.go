package trunk

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

const noTimerCfg = `
listen:
  sip: [udp://127.0.0.1:13220]
  media:
    port_range: 13224-13227
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:13221
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// audit: P2-TRK-009
// RFC 4028 §9: a UAS may name the UAC as refresher only when the UAC said
// Supported: timer. A caller that did not must not be told to refresh.
func TestALegNoTimerWithoutSupported(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:13221", testSDPBody(uacRTPStubPort(t)))
	srv := startServer(t, 13220, noTimerCfg)
	uac := startTestUAC(t, "127.0.0.1:13222")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess := uac.call(t, ctx, 13220, nil)
	res := sess.InviteResponse
	if se := res.GetHeaders("Session-Expires"); len(se) != 0 {
		t.Errorf("A-leg 200 to a caller without Supported: timer carries Session-Expires %q", se[0].Value())
	}
	if req := res.GetHeaders("Require"); hasToken(req, "timer") {
		t.Errorf("A-leg 200 to a caller without Supported: timer carries Require: timer")
	}
	if err := sess.Bye(ctx); err != nil {
		t.Fatalf("bye: %v", err)
	}
	<-carrier.byeDone
	waitForActiveCalls(t, srv, 0, 3*time.Second)
}

// withHeaders inserts extra header lines into a raw SIP message, just
// after its start line.
func withHeaders(msg string, lines ...string) string {
	i := strings.Index(msg, "\r\n")
	return msg[:i+2] + strings.Join(lines, "\r\n") + "\r\n" + msg[i+2:]
}

// rawRefreshCarrier answers the first INVITE 200 with a session timer that
// makes the SBC (the B-leg UAC) the refresher, then answers every refresh
// re-INVITE 200 and delivers it, and every ACK, to reqs.
type rawRefreshCarrier struct {
	reqs chan string
}

func startRawRefreshCarrier(t *testing.T, addr string, answer []byte, sessionExpires string) *rawRefreshCarrier {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &rawRefreshCarrier{reqs: make(chan string, 32)}
	contact := conn.LocalAddr().String()
	go func() {
		buf := make([]byte, 65535)
		answered := false
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			text := string(buf[:n])
			lines := rawHeaderLines(text)
			switch rawMethod(text) {
			case "INVITE":
				if rawToTag(text) == "" {
					if answered {
						continue // retransmission
					}
					answered = true
					_, _ = conn.WriteToUDP([]byte(withHeaders(rawFinalResponse(200, "OK", lines, "carrier-tag", contact, answer),
						"Session-Expires: "+sessionExpires, "Require: timer")), src)
					continue
				}
				c.reqs <- text
				_, _ = conn.WriteToUDP([]byte(withHeaders(rawFinalResponse(200, "OK", lines, "", contact, answer),
					"Session-Expires: "+sessionExpires, "Require: timer")), src)
			case "ACK":
				c.reqs <- text
			case "BYE":
				_, _ = conn.WriteToUDP([]byte(rawFinalResponse(200, "OK", lines, "", contact, nil)), src)
			}
		}
	}()
	return c
}

const sbcRefreshesCfg = `
listen:
  sip: [udp://127.0.0.1:13230]
  media:
    port_range: 13234-13237
    public_ip: 127.0.0.1
session_expires: 4s
min_se: 1s
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:13231
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// audit: P2-TRK-009
// RFC 4028 §7.2 / §10: when the carrier's 2xx names the SBC (the B-leg UAC)
// as refresher, the SBC must refresh before the interval runs out, or the
// carrier BYEs the call. With Session-Expires: 2 the refresh is due at 1s.
func TestSBCRefreshesWhenCarrierMakesItRefresher(t *testing.T) {
	carrier := startRawRefreshCarrier(t, "127.0.0.1:13231", testSDPBody(13238), "2;refresher=uac")
	startServer(t, 13230, sbcRefreshesCfg)
	uac := startTestUAC(t, "127.0.0.1:13232")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess := uac.call(t, ctx, 13230, nil)
	defer func() { _ = sess.Bye(ctx) }()

	var refreshes, acks int
	deadline := time.After(3500 * time.Millisecond)
	for refreshes < 2 || acks < 2 {
		select {
		case req := <-carrier.reqs:
			switch rawMethod(req) {
			case "INVITE":
				refreshes++
				if !strings.Contains(req, "Session-Expires: 2;refresher=uac") {
					t.Errorf("refresh re-INVITE does not keep the SBC as refresher:\n%s", req)
				}
				if rawToTag(req) != "carrier-tag" {
					t.Errorf("refresh re-INVITE is not on the carrier's dialog:\n%s", req)
				}
			case "ACK":
				if rawToTag(req) == "carrier-tag" && strings.Contains(req, " ACK\r\n") {
					acks++
				}
			}
		case <-deadline:
			t.Fatalf("SBC sent %d refresh re-INVITEs and %d ACKs within 3.5s, want at least 2 of each (Session-Expires: 2)", refreshes, acks)
		}
	}
}

const refreshRetransmitCfg = `
listen:
  sip: [udp://127.0.0.1:13240]
  media:
    port_range: 13244-13247
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:13241
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// audit: P2-TRK-015
// RFC 3261 §13.3.1.4: the UAS core retransmits a 2xx to INVITE until the
// ACK arrives. A lost refresh 200 must be retransmitted, and the ACK must
// stop it.
func TestRefresh200RetransmittedUntilAck(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:13241", testSDPBody(uacRTPStubPort(t)))
	srv := startServer(t, 13240, refreshRetransmitCfg)
	uac := startTestUAC(t, "127.0.0.1:13242")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess := uac.call(t, ctx, 13240, nil)
	waitForActiveCalls(t, srv, 1, 3*time.Second)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 13240}
	fromTag, _ := sess.InviteRequest.From().Params.Get("tag")
	toTag, _ := sess.InviteResponse.To().Params.Get("tag")
	callID := sess.InviteRequest.CallID().Value()
	body := sess.InviteRequest.Body()
	msg := func(method string) string {
		lines := []string{
			fmt.Sprintf("%s sip:5551234@127.0.0.1:13240 SIP/2.0", method),
			fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-refresh-%s", local, strings.ToLower(method)),
			"From: <sip:tester@127.0.0.1>;tag=" + fromTag,
			"To: <sip:sbc@127.0.0.1>;tag=" + toTag,
			"Call-ID: " + callID,
			fmt.Sprintf("CSeq: 5 %s", method),
			"Contact: <sip:tester@" + local.String() + ">",
			"Max-Forwards: 70",
		}
		if method == "ACK" {
			return strings.Join(append(lines, "Content-Length: 0", "", ""), "\r\n")
		}
		return strings.Join(append(lines,
			"Session-Expires: 1800;refresher=uac",
			"Supported: timer",
			"Content-Type: application/sdp",
			fmt.Sprintf("Content-Length: %d", len(body)),
			"", string(body)), "\r\n")
	}
	if _, err := conn.WriteToUDP([]byte(msg("INVITE")), dst); err != nil {
		t.Fatal(err)
	}
	if got, ok := readUntil(t, conn, "SIP/2.0 200", 3*time.Second); !ok {
		t.Fatalf("refresh re-INVITE got no 200:\n%s", got)
	}
	// Treat that 200 as lost: a retransmission must follow within 2·T1.
	if got, ok := readUntil(t, conn, "SIP/2.0 200", 2*sip.T1+300*time.Millisecond); !ok {
		t.Fatalf("refresh 200 was not retransmitted within 2·T1:\n%s", got)
	}
	if _, err := conn.WriteToUDP([]byte(msg("ACK")), dst); err != nil {
		t.Fatal(err)
	}
	// Let a retransmission already in flight land, then expect silence.
	time.Sleep(200 * time.Millisecond)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if _, _, err := conn.ReadFromUDP(make([]byte, 8192)); err != nil {
			break
		}
	}
	if got, ok := readUntil(t, conn, "SIP/2.0 200", 2*time.Second); ok {
		t.Fatalf("refresh 200 still retransmitted after its ACK:\n%s", got)
	}

	if err := sess.Bye(ctx); err != nil {
		t.Fatalf("bye: %v", err)
	}
	<-carrier.byeDone
	waitForActiveCalls(t, srv, 0, 3*time.Second)
}
