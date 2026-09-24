package sip

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Unit tests for the shared primitives. Most of these functions are also
// exercised end to end by the trunk and edge suites, but a regression in
// one of them should fail here, next to the code, and not only as an
// unexplained call failure two packages away (audit P1-010).

func parseRequest(t *testing.T, raw string) *sip.Request {
	t.Helper()
	msg, err := sip.NewParser().ParseSIP([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	req, ok := msg.(*sip.Request)
	if !ok {
		t.Fatalf("not a request: %T", msg)
	}
	return req
}

func parseResponse(t *testing.T, raw string) *sip.Response {
	t.Helper()
	msg, err := sip.NewParser().ParseSIP([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, ok := msg.(*sip.Response)
	if !ok {
		t.Fatalf("not a response: %T", msg)
	}
	return res
}

const testInvite = "INVITE sip:1000@192.0.2.10:5060 SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK-inv1\r\n" +
	"Route: <sip:192.0.2.1;lr>\r\n" +
	"Max-Forwards: 70\r\n" +
	"From: <sip:alice@example.com>;tag=from-1\r\n" +
	"To: <sip:1000@example.com>\r\n" +
	"Call-ID: call-1@example.com\r\n" +
	"CSeq: 7 INVITE\r\n" +
	"Contact: <sip:alice@198.51.100.1:5060>\r\n" +
	"Contact: <sip:alice@198.51.100.2:5060>\r\n" +
	"User-Agent: TestPhone/1.0\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 0\r\n" +
	"\r\n"

const test200 = "SIP/2.0 200 OK\r\n" +
	"Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK-inv1\r\n" +
	"From: <sip:alice@example.com>;tag=from-1\r\n" +
	"To: <sip:1000@example.com>;tag=to-1\r\n" +
	"Call-ID: call-1@example.com\r\n" +
	"CSeq: 7 INVITE\r\n" +
	"Contact: <sip:1000@192.0.2.10:5070>\r\n" +
	"Content-Length: 0\r\n" +
	"\r\n"

func TestSourceAddrPort(t *testing.T) {
	req := parseRequest(t, testInvite)
	for _, tc := range []struct {
		src  string
		want string
		ok   bool
	}{
		{"198.51.100.1:5060", "198.51.100.1:5060", true},
		{"[::ffff:198.51.100.1]:5062", "198.51.100.1:5062", true}, // unmapped
		{"[2001:db8::1]:5060", "[2001:db8::1]:5060", true},
		{"198.51.100.1", "", false},
		{"host.example:5060", "", false},
		{"198.51.100.1:port", "", false},
	} {
		req.SetSource(tc.src)
		got, ok := SourceAddrPort(req)
		if ok != tc.ok {
			t.Errorf("SourceAddrPort(%q) ok = %v, want %v", tc.src, ok, tc.ok)
			continue
		}
		if ok && got.String() != tc.want {
			t.Errorf("SourceAddrPort(%q) = %s, want %s", tc.src, got, tc.want)
		}
	}
}

func TestParseHostPortAddrAndAddrOf(t *testing.T) {
	if got, ok := ParseHostPortAddr("[::ffff:192.0.2.7]:5060"); !ok || got != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("ParseHostPortAddr(4in6) = %v, %v; want 192.0.2.7, true", got, ok)
	}
	for _, bad := range []string{"192.0.2.7", "name.example:5060", ""} {
		if _, ok := ParseHostPortAddr(bad); ok {
			t.Errorf("ParseHostPortAddr(%q) ok = true, want false", bad)
		}
	}
	if _, ok := AddrOf(nil); ok {
		t.Error("AddrOf(nil) ok = true, want false")
	}
	got, ok := AddrOf(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5060})
	if !ok || got != netip.MustParseAddr("10.0.0.9") {
		t.Errorf("AddrOf(udp 10.0.0.9) = %v, %v", got, ok)
	}
}

// TestSameAddrExactMatch covers only the exact-host cases. How a wildcard
// host or a differing transport should compare is open (audit P2-SIP-004)
// and deliberately not pinned here.
func TestSameAddrExactMatch(t *testing.T) {
	if !SameAddr("192.0.2.1:5060", "192.0.2.1:5060") {
		t.Error("identical addresses must match")
	}
	if SameAddr("192.0.2.1:5060", "192.0.2.1:5061") {
		t.Error("different ports must not match")
	}
	if SameAddr("192.0.2.1:5060", "192.0.2.2:5060") {
		t.Error("different concrete hosts must not match")
	}
	if !SameAddr("garbage", "garbage") || SameAddr("garbage", "other") {
		t.Error("unparseable inputs must fall back to string equality")
	}
}

// TestDefaultPort pins the RFC 3261 defaults. The wss mapping is left to
// audit P2-SIP-007.
func TestDefaultPort(t *testing.T) {
	for tr, want := range map[string]int{"udp": 5060, "TCP": 5060, "tls": 5061, "TLS": 5061, "ws": 80, "": 5060} {
		if got := DefaultPort(tr); got != want {
			t.Errorf("DefaultPort(%q) = %d, want %d", tr, got, want)
		}
	}
}

func TestRemoveHeadersAndSetContact(t *testing.T) {
	req := parseRequest(t, testInvite)
	if n := len(req.GetHeaders("Contact")); n != 2 {
		t.Fatalf("fixture has %d Contacts, want 2", n)
	}
	RemoveHeaders(req, "User-Agent")
	if req.GetHeader("User-Agent") != nil {
		t.Error("RemoveHeaders left a User-Agent")
	}
	RemoveHeaders(req, "X-Absent") // must terminate on a missing header

	u := sip.Uri{User: "sbc", Host: "203.0.113.5", Port: 5080}
	SetContact(req, u)
	hs := req.GetHeaders("Contact")
	if len(hs) != 1 {
		t.Fatalf("SetContact left %d Contacts, want exactly 1", len(hs))
	}
	if got, ok := ContactURI(req); !ok || got.Host != "203.0.113.5" || got.Port != 5080 {
		t.Errorf("ContactURI after SetContact = %v, %v", got, ok)
	}
}

func TestSetSDPBody(t *testing.T) {
	req := parseRequest(t, testInvite)
	req.AppendHeader(sip.NewHeader("Content-Type", "text/plain"))
	body := []byte("v=0\r\n")
	SetSDPBody(req, body)
	cts := req.GetHeaders("Content-Type")
	if len(cts) != 1 || cts[0].Value() != "application/sdp" {
		t.Errorf("Content-Type after SetSDPBody = %v, want one application/sdp", cts)
	}
	if string(req.Body()) != string(body) {
		t.Errorf("body = %q, want %q", req.Body(), body)
	}
	if cl := req.ContentLength(); cl == nil || int(*cl) != len(body) {
		t.Errorf("Content-Length = %v, want %d", cl, len(body))
	}
}

func TestMessageAccessors(t *testing.T) {
	req := parseRequest(t, testInvite)
	if got := CallID(req); got != "call-1@example.com" {
		t.Errorf("CallID = %q", got)
	}
	if got := FromTag(req); got != "from-1" {
		t.Errorf("FromTag = %q", got)
	}
	if got := ToTag(req); got != "" {
		t.Errorf("ToTag on an initial INVITE = %q, want empty", got)
	}
	if got := UserAgent(req); got != "TestPhone/1.0" {
		t.Errorf("UserAgent = %q", got)
	}
	if got := CSeqNumber(req); got != 7 {
		t.Errorf("CSeqNumber = %d, want 7", got)
	}
	if u, ok := ContactURI(req); !ok || u.Host != "198.51.100.1" {
		t.Errorf("ContactURI = %v, %v; want the first Contact", u, ok)
	}

	res := parseResponse(t, test200)
	if got := ToTag(res); got != "to-1" {
		t.Errorf("ToTag(200) = %q", got)
	}

	// A message stripped of the headers must yield zero values, never panic.
	bare := sip.NewRequest(sip.OPTIONS, sip.Uri{Host: "192.0.2.1"})
	if CallID(bare) != "" || FromTag(bare) != "" || ToTag(bare) != "" || UserAgent(bare) != "" {
		t.Error("accessors on a bare request must return empty strings")
	}
	if CSeqNumber(bare) != 1 {
		t.Errorf("CSeqNumber(no CSeq) = %d, want 1", CSeqNumber(bare))
	}
	if _, ok := ContactURI(bare); ok {
		t.Error("ContactURI(no Contact) ok = true")
	}
}

func TestNewBranchAndToken(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		b := NewBranch()
		if !strings.HasPrefix(b, "z9hG4bK") || len(b) <= len("z9hG4bK")+8 {
			t.Fatalf("NewBranch() = %q, want the RFC 3261 magic cookie plus a random suffix", b)
		}
		tok := NewToken()
		if len(tok) != 16 { // 12 bytes, raw URL base64
			t.Fatalf("NewToken() = %q, want 16 characters", tok)
		}
		if strings.ContainsAny(tok, "+/=") {
			t.Fatalf("NewToken() = %q is not URL-safe", tok)
		}
		if seen[b] || seen[tok] {
			t.Fatal("NewBranch/NewToken repeated a value")
		}
		seen[b], seen[tok] = true, true
	}
}

func TestReadFilter(t *testing.T) {
	data := []byte("OPTIONS sip:x SIP/2.0\r\n\r\n")
	props := sip.TransportReadProps{}

	pass := ReadFilter(0, nil)
	if got, err := pass(props, data); err != nil || string(got) != string(data) {
		t.Errorf("uncapped, nil accept: got %q, %v", got, err)
	}

	capped := ReadFilter(len(data)-1, nil)
	if got, err := capped(props, data); err != nil || got != nil {
		t.Errorf("oversized read: got %q, %v; want nil, nil (a filter must never return an error)", got, err)
	}

	calls := 0
	deny := ReadFilter(len(data), func(sip.TransportReadProps) bool { calls++; return false })
	if got, err := deny(props, data); err != nil || got != nil {
		t.Errorf("rejected read: got %q, %v; want nil, nil", got, err)
	}
	if calls != 1 {
		t.Errorf("accept called %d times, want 1", calls)
	}
	if _, _ = deny(props, append(data, 'x')); calls != 1 {
		t.Error("accept must not run for a read that already failed the size cap")
	}
}

func TestGrantedExpires(t *testing.T) {
	const base = "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK-r1\r\n" +
		"From: <sip:u@example.com>;tag=a\r\n" +
		"To: <sip:u@example.com>;tag=b\r\n" +
		"Call-ID: reg-1\r\n" +
		"CSeq: 1 REGISTER\r\n"
	for _, tc := range []struct {
		name  string
		extra string
		want  time.Duration
	}{
		{"contact param wins", "Contact: <sip:u@198.51.100.1>;expires=120\r\nExpires: 600\r\n", 120 * time.Second},
		{"expires header", "Contact: <sip:u@198.51.100.1>\r\nExpires: 600\r\n", 600 * time.Second},
		{"nothing granted", "", 3600 * time.Second},
		{"garbage falls back", "Expires: soon\r\n", 3600 * time.Second},
	} {
		res := parseResponse(t, base+tc.extra+"Content-Length: 0\r\n\r\n")
		if got := GrantedExpires(res, time.Hour); got != tc.want {
			t.Errorf("%s: GrantedExpires = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestParseBindIP pins the valid-input cases. The fallback for an
// unparseable value is audit P2-SIP-008's to decide.
func TestParseBindIP(t *testing.T) {
	if got := ParseBindIP(""); got.IsValid() {
		t.Errorf("ParseBindIP(\"\") = %v, want the zero Addr", got)
	}
	if got := ParseBindIP("10.1.2.3"); got != netip.MustParseAddr("10.1.2.3") {
		t.Errorf("ParseBindIP(10.1.2.3) = %v", got)
	}
}

func TestForwardable(t *testing.T) {
	for code, want := range map[int]bool{100: false, 180: true, 183: true, 200: true, 486: true} {
		if got := Forwardable(&sip.Response{StatusCode: code}); got != want {
			t.Errorf("Forwardable(%d) = %v, want %v", code, got, want)
		}
	}
}

func TestBuildCancel(t *testing.T) {
	inv := parseRequest(t, testInvite)
	inv.SetTransport("UDP")
	inv.SetDestination("192.0.2.10:5060")
	inv.Laddr = sip.Addr{IP: net.IPv4(192, 0, 2, 1), Port: 5060}

	c := BuildCancel(inv)
	if c.Method != sip.CANCEL {
		t.Fatalf("method = %s", c.Method)
	}
	if c.Recipient.String() != inv.Recipient.String() {
		t.Errorf("Request-URI = %s, want the INVITE's %s", c.Recipient.String(), inv.Recipient.String())
	}
	if v := c.Via(); v == nil || v.Params == nil {
		t.Fatal("CANCEL has no Via")
	} else if b, _ := v.Params.Get("branch"); b != "z9hG4bK-inv1" {
		t.Errorf("Via branch = %q, want the INVITE's", b)
	}
	if len(c.GetHeaders("Via")) != 1 {
		t.Errorf("CANCEL carries %d Vias, want only the top one", len(c.GetHeaders("Via")))
	}
	if CallID(c) != "call-1@example.com" || FromTag(c) != "from-1" {
		t.Error("CANCEL must copy Call-ID and From")
	}
	if r := c.GetHeader("Route"); r == nil {
		t.Error("CANCEL must copy the INVITE's Route set")
	}
	if cs := c.CSeq(); cs == nil || cs.SeqNo != 7 || cs.MethodName != sip.CANCEL {
		t.Errorf("CSeq = %v, want 7 CANCEL", cs)
	}
	if c.Destination() != "192.0.2.10:5060" || c.Transport() != "UDP" || !c.Laddr.IP.Equal(inv.Laddr.IP) {
		t.Error("CANCEL must leave by the INVITE's transport, destination and local address")
	}
	if len(c.Body()) != 0 {
		t.Error("CANCEL must have no body")
	}
}

func TestTeardownRequestAndContactOrSource(t *testing.T) {
	res := parseResponse(t, test200)
	res.SetSource("192.0.2.10:5060")
	via := sip.NewHeader("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-bye")

	bye := TeardownRequest(sip.BYE, res, via, 8)
	if bye.Method != sip.BYE {
		t.Fatalf("method = %s", bye.Method)
	}
	if bye.Recipient.Host != "192.0.2.10" || bye.Recipient.Port != 5070 {
		t.Errorf("Request-URI = %s, want the 2xx Contact", bye.Recipient.String())
	}
	if FromTag(bye) != "from-1" || ToTag(bye) != "to-1" || CallID(bye) != "call-1@example.com" {
		t.Error("BYE must carry the dialog identifiers of the 2xx")
	}
	if cs := bye.CSeq(); cs == nil || cs.SeqNo != 8 || cs.MethodName != sip.BYE {
		t.Errorf("CSeq = %v, want 8 BYE", cs)
	}
	if bye.Destination() != "192.0.2.10:5060" {
		t.Errorf("destination = %q, want the 2xx's transport source", bye.Destination())
	}

	// Without a Contact the target falls back to the transport source.
	RemoveHeaders(res, "Contact")
	if u := ContactOrSource(res); u.Host != "192.0.2.10" || u.Port != 5060 {
		t.Errorf("ContactOrSource(no Contact) = %s, want the source", u.String())
	}
	res.SetSource("not-a-hostport")
	if u := ContactOrSource(res); u.Host != "not-a-hostport" {
		t.Errorf("ContactOrSource(bad source) = %s", u.String())
	}
}
