package sip

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Audit tests (docs/audit/REPORT.md). A failing test here is the
// deliverable: it demonstrates a defect. Do not make it pass by editing the
// test; fix the production code instead.

func auditParseResponse(t testing.TB, raw string) *sip.Response {
	t.Helper()
	msg, err := sip.NewParser().ParseSIP([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, ok := msg.(*sip.Response)
	if !ok {
		t.Fatalf("not a response: %T", msg)
	}
	res.SetSource("198.51.100.1:5060")
	return res
}

const auditRegister200 = "SIP/2.0 200 OK\r\n" +
	"Via: SIP/2.0/UDP 10.77.0.2:16060;branch=z9hG4bK-1\r\n" +
	"From: <sip:1000@pbx>;tag=a\r\n" +
	"To: <sip:1000@pbx>;tag=b\r\n" +
	"Call-ID: reg-1\r\n" +
	"CSeq: 1 REGISTER\r\n" +
	"Contact: <sip:1000@10.77.0.2:16060;fsbc=THEIRS>;expires=%s\r\n" +
	"Content-Length: 0\r\n\r\n"

// audit: P2-SIP-001
// RFC 3261 §10.2.4 / §10.3: expires is delta-seconds (non-negative). A
// negative value or one that overflows time.Duration must not come back as
// a negative lifetime (the edge treats <= 0 as "binding removed").
func TestAuditGrantedExpiresRejectsNegativeAndOverflow(t *testing.T) {
	for _, v := range []string{"-1", "99999999999", "9223372037"} {
		t.Run(v, func(t *testing.T) {
			res := auditParseResponse(t, strings.Replace(auditRegister200, "%s", v, 1))
			if got := GrantedExpires(res, time.Hour); got < 0 {
				t.Errorf("GrantedExpires(expires=%s) = %v, a negative lifetime", v, got)
			}
		})
	}
}

// audit: P2-SIP-002
// The edge read filter caps reads at 64 KiB (edge/edge.go:459-469), but
// every sipgo transport reads into a TransportBufferReadSize buffer, so the
// cap can never be exceeded and the reject branch is dead.
func TestAuditReadFilterCapIsReachable(t *testing.T) {
	const edgeCap = 64 << 10
	if int(sip.TransportBufferReadSize) <= edgeCap {
		t.Errorf("sipgo reads at most %d bytes per read; the %d-byte filter cap can never fire",
			sip.TransportBufferReadSize, edgeCap)
	}
}

// audit: P2-SIP-005
// RFC 3261 §12.1.2 / §13.2.2.4: the ACK/BYE for a 2xx follows the route
// set, which is the Record-Route list reversed.
func TestAuditTeardownRequestHonoursRouteSet(t *testing.T) {
	res := auditParseResponse(t, "SIP/2.0 200 OK\r\n"+
		"Via: SIP/2.0/UDP 10.77.0.2:16060;branch=z9hG4bK-2\r\n"+
		"Record-Route: <sip:p1.example;lr>\r\n"+
		"Record-Route: <sip:p2.example;lr>\r\n"+
		"From: <sip:a@x>;tag=a\r\nTo: <sip:b@y>;tag=b\r\nCall-ID: c-1\r\nCSeq: 1 INVITE\r\n"+
		"Contact: <sip:b@198.51.100.1:5060>\r\nContent-Length: 0\r\n\r\n")
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "10.77.0.2", Port: 16060, Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranch())
	ack := TeardownRequest(sip.ACK, res, via, 1)
	var routes []string
	for _, h := range ack.GetHeaders("Route") {
		routes = append(routes, h.Value())
	}
	got := strings.Join(routes, ",")
	if !strings.Contains(got, "p2.example") || strings.Index(got, "p2.example") > strings.Index(got, "p1.example") {
		t.Errorf("ACK Route = %q, want the reversed Record-Route set (p2, p1)", got)
	}
}

// audit: P2-SIP-006
// SetSDPBody must leave the message with a typed Content-Type.
func TestAuditSetSDPBodyTypedContentType(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "b", Host: "y"})
	SetSDPBody(req, []byte("v=0\r\n"))
	if req.ContentType() == nil {
		t.Errorf("ContentType() is nil after SetSDPBody; header is %q", req.GetHeader("Content-Type"))
	}
}

// audit: fuzz (crash hunt)
// Received bytes go through sipgo's parser and then through every helper in
// this package that reads attacker-controlled fields. None may panic.
func FuzzAuditSIPMessageHelpers(f *testing.F) {
	f.Add([]byte(strings.Replace(auditRegister200, "%s", "3600", 1)))
	f.Add([]byte("INVITE sip:b@y SIP/2.0\r\n" +
		"v: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK-3,SIP/2.0/TCP 10.0.0.1;branch=z9hG4bK-4\r\n" +
		"f: <sip:a@x>;tag=a\r\nt: <sip:b@y>\r\ni: c-2\r\nCSeq: 1 INVITE\r\n" +
		"m: <sip:a@198.51.100.1>;expires=10, <sip:a2@198.51.100.2>\r\n" +
		"User-Agent: friendly-scanner\r\nc: application/sdp\r\nl: 5\r\n\r\nv=0\r\n"))
	f.Add([]byte("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK-5\r\nRecord-Route: <sip:p1;lr>,<sip:p2;lr>\r\n" +
		"From: <sip:a@x>;tag=a\r\nTo: <sip:b@y>;tag=b\r\nCall-ID: c\r\nCSeq: 2 INVITE\r\nExpires: 60\r\n" +
		"Contact: *\r\nContent-Length: 0\r\n\r\n"))
	filter := ReadFilter(64<<10, func(sip.TransportReadProps) bool { return true })
	props := sip.TransportReadProps{Transport: "udp",
		LocalAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5060}, RemoteAddr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 5060}}
	f.Fuzz(func(t *testing.T, data []byte) {
		if out, err := filter(props, data); err != nil || (out == nil && len(data) <= 64<<10) {
			t.Fatalf("ReadFilter returned (%v, %v) for an in-cap read", out == nil, err)
		}
		_ = SameAddr(string(data), "0.0.0.0:5060")
		_ = ParseBindIP(string(data))
		msg, err := sip.NewParser().ParseSIP(data)
		if err != nil {
			return
		}
		msg.SetSource("198.51.100.1:5060")
		_ = CallID(msg)
		_ = FromTag(msg)
		_ = ToTag(msg)
		_, _ = ContactURI(msg)
		_ = CSeqNumber(msg)
		switch m := msg.(type) {
		case *sip.Request:
			_ = UserAgent(m)
			_, _ = SourceAddrPort(m)
			if m.Method == sip.INVITE {
				_ = BuildCancel(m).String()
			}
			SetContact(m, sip.Uri{Host: "10.0.0.1", Port: 5060})
			SetSDPBody(m, []byte("v=0\r\n"))
			RemoveHeaders(m, "Via")
			_ = m.String()
		case *sip.Response:
			_ = Forwardable(m)
			_ = GrantedExpires(m, time.Hour)
			_ = ContactOrSource(m)
			via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "10.0.0.1", Port: 5060, Params: sip.NewParams()}
			_ = TeardownRequest(sip.BYE, m, via, CSeqNumber(m)+1).String()
			_ = m.String()
		}
	})
}
