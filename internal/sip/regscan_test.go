package sip

import (
	"strings"
	"testing"
)

const scanRegister = "REGISTER sip:example.com SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 198.51.100.7:5060;rport;branch=z9hG4bK-one\r\n" +
	"Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK-two\r\n" +
	"From: <sip:1001@example.com>;tag=f\r\n" +
	"To: \"Alice\" <sip:1001@Example.COM:5060;transport=udp>\r\n" +
	"Call-ID: reg-abc@198.51.100.7\r\n" +
	"CSeq: 2 REGISTER\r\n" +
	"Authorization: Digest username=\"1001\", realm=\"example.com\", nonce=\"n-1\",\r\n" +
	" uri=\"sip:example.com\", response=\"0123abcd\", algorithm=MD5\r\n" +
	"Content-Length: 0\r\n\r\n"

func TestScanRegister(t *testing.T) {
	h, ok := ScanRegister([]byte(scanRegister))
	if !ok {
		t.Fatal("not recognised as a REGISTER")
	}
	if h.Branch != "z9hG4bK-one" {
		t.Errorf("branch = %q, want the topmost Via's", h.Branch)
	}
	if h.CallID != "reg-abc@198.51.100.7" {
		t.Errorf("call-id = %q", h.CallID)
	}
	if h.AOR != "1001@example.com" {
		t.Errorf("aor = %q", h.AOR)
	}
	if !h.Auth || h.Nonce != "n-1" || h.AuthKey == 0 {
		t.Errorf("auth = %v nonce = %q key = %x", h.Auth, h.Nonce, h.AuthKey)
	}
	if h.User != "1001" {
		t.Errorf("user = %q, want the folded Authorization's username", h.User)
	}
	// The folded line belongs to the Authorization header, so the key is
	// the one a parsed header value gives.
	_, _, want := DigestIdentity(`Digest username="1001",realm="example.com",nonce="n-1",uri="sip:example.com",response="0123abcd",algorithm=MD5`)
	if h.AuthKey != want {
		t.Errorf("raw and parsed attempt keys differ: %x != %x", h.AuthKey, want)
	}
}

func TestScanRegisterCompactAndNoAuth(t *testing.T) {
	raw := "REGISTER sip:x SIP/2.0\r\nv: SIP/2.0/UDP h;BRANCH=b1, SIP/2.0/UDP g;branch=b2\r\n" +
		"t: sip:Bob@X.org;tag=1\r\ni: cid\r\n\r\n"
	h, ok := ScanRegister([]byte(raw))
	if !ok || h.Branch != "b1" || h.CallID != "cid" || h.AOR != "bob@x.org" || h.Auth {
		t.Errorf("got %+v, %v", h, ok)
	}
}

func TestScanRegisterProxyAuthorization(t *testing.T) {
	raw := "REGISTER sip:x SIP/2.0\r\nproxy-authorization: Digest Username=\"Bob\", nonce=\"pn\", response=\"r\"\r\n\r\n"
	if h, ok := ScanRegister([]byte(raw)); !ok || !h.Auth || h.Nonce != "pn" || h.User != "Bob" {
		t.Errorf("got %+v, %v", h, ok)
	}
}

func TestScanRegisterNotRegister(t *testing.T) {
	for _, raw := range []string{"", "INVITE sip:x SIP/2.0\r\n\r\n", "register sip:x SIP/2.0\r\n\r\n", "SIP/2.0 401 Unauthorized\r\n\r\n"} {
		if _, ok := ScanRegister([]byte(raw)); ok {
			t.Errorf("%q recognised as a REGISTER", raw)
		}
	}
}

// Headers after the blank line are body, not headers.
func TestScanRegisterStopsAtBody(t *testing.T) {
	raw := "REGISTER sip:x SIP/2.0\r\nCall-ID: c\r\n\r\nAuthorization: Digest nonce=\"x\"\r\n"
	if h, _ := ScanRegister([]byte(raw)); h.Auth {
		t.Error("a body line was read as a header")
	}
}

func TestScanRegisterMalformedTo(t *testing.T) {
	for _, to := range []string{"<sip:example.com>", "<sip:a b@x>", "<tel:123>", "<sip:a@x", "sip:@x", "\"x\" <sip:a;b@x>"} {
		raw := "REGISTER sip:x SIP/2.0\r\nTo: " + to + "\r\n\r\n"
		if h, _ := ScanRegister([]byte(raw)); h.AOR != "" {
			t.Errorf("To %q: aor = %q, want empty", to, h.AOR)
		}
	}
}

func TestNormalizeAOR(t *testing.T) {
	if aor, ok := NormalizeAOR("Alice", "Example.com"); !ok || aor != "alice@example.com" {
		t.Errorf("got %q, %v", aor, ok)
	}
	for _, bad := range [][2]string{{"", "x"}, {"a", ""}, {"a@b", "x"}, {"a", "x;y"}, {strings.Repeat("a", 129), "x"}} {
		if _, ok := NormalizeAOR(bad[0], bad[1]); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDigestParam(t *testing.T) {
	v := `Digest realm="a, b", nonce="x\"y", algorithm=MD5, qop="auth"`
	for name, want := range map[string]string{"realm": "a, b", "NONCE": `x"y`, "algorithm": "MD5", "qop": "auth"} {
		if got, ok := DigestParam(v, name); !ok || got != want {
			t.Errorf("%s = %q, %v; want %q", name, got, ok, want)
		}
	}
	if _, ok := DigestParam(v, "opaque"); ok {
		t.Error("absent param found")
	}
}

// Two attempts differing only in the response are distinct; spacing and
// quoting are not.
func TestDigestAttemptKey(t *testing.T) {
	_, n1, a := DigestIdentity(`Digest username="u", nonce="n", response="r1"`)
	_, _, b := DigestIdentity(`Digest username="u", nonce="n", response="r2"`)
	_, _, c := DigestIdentity(`Digest   username=u,nonce="n" ,  response="r1"`)
	if n1 != "n" || a == b || a != c {
		t.Errorf("nonce %q keys %x %x %x", n1, a, b, c)
	}
}

// DigestIdentity returns the username as sent, quoted or not, "" when
// absent.
func TestDigestIdentity(t *testing.T) {
	for _, tc := range []struct{ in, user string }{
		{`Digest username="u", nonce="n", response="r"`, "u"},
		{`Digest   USERNAME=u2,nonce="n"`, "u2"},
		{`Digest username="a\"b", nonce="n", response="r"`, `a"b`},
		{`Digest nonce="n", response="r"`, ""},
		{``, ""},
	} {
		user, nonce, key := DigestIdentity(tc.in)
		if user != tc.user {
			t.Errorf("%q: user %q (nonce %q key %x), want %q", tc.in, user, nonce, key, tc.user)
		}
	}
}

func FuzzRegisterScan(f *testing.F) {
	f.Add([]byte(scanRegister))
	f.Add([]byte("REGISTER sip:x SIP/2.0\nv:;branch\nt:<sip:@>\nAuthorization: Digest nonce=\"\\"))
	f.Add([]byte("REGISTER \r\n\t folded\r\nTo: \"<\" <sip:a@[::1]:5060>\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, ok := ScanRegister(data)
		if !ok && h != (RegisterHead{}) {
			t.Fatalf("non-REGISTER produced %+v", h)
		}
		if h.AOR != "" {
			if strings.ContainsAny(h.AOR, " \t\r\n<>;,\"") {
				t.Fatalf("aor %q carries a structural character", h.AOR)
			}
		}
		DigestParam(string(data), "nonce")
		DigestIdentity(string(data))
	})
}
