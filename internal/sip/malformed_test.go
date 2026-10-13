package sip

import "testing"

const okInvite = "INVITE sip:b@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n" +
	"From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n" +
	"Content-Length: 4\r\n\r\nbody"

func TestMalformed(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"request", okInvite, false},
		{"request no body", "OPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\n\r\n", false},
		{"lowercase sip", "OPTIONS sip:x sip/2.0\r\nCall-ID: c\r\n\r\n", false},
		{"response", "SIP/2.0 200 OK\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\n\r\n", false},
		{"response short reason", "SIP/2.0 200 OK\r\n\r\n", false},
		{"no headers", "OPTIONS sip:x SIP/2.0\r\n\r\n", false},
		{"folded header", "OPTIONS sip:x SIP/2.0\r\nSubject: a\r\n  b no colon here\r\n\tmore\r\nCall-ID: c\r\n\r\n", false},
		{"colon on a continuation line", "OPTIONS sip:x SIP/2.0\r\nSubject\r\n : x\r\nCall-ID: c\r\n\r\n", false},
		{"body with colonless lines", "MESSAGE sip:x SIP/2.0\r\nCall-ID: c\r\n\r\nno colon\r\nhere", false},
		{"keep-alive crlf", "\r\n", false},
		{"keep-alive crlfcrlf", "\r\n\r\n", false},
		{"nul padding", "\x00\x00\x00", false},
		{"empty", "", false},

		{"plain text", "hello world", true},
		{"one space start line", "INVITE sip:a@b\r\n\r\n", true},
		{"not sip start line", "NOTSIP 1 Authorization: x\r\n\r\n", true},
		{"wrong version case", "INVITE sip:a Sip/2.0\r\nCall-ID: c\r\n\r\n", true},
		{"no end of headers", "OPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\n", true},
		{"start line unterminated", "OPTIONS sip:x SIP/2.0", true},
		{"bare cr start line", "OPTIONS sip:x SIP/2.0\rCall-ID: c\r\n\r\n", true},
		{"bare lf only", "OPTIONS sip:x SIP/2.0\nCall-ID: c\n\n", true},
		{"leading crlf", "\r\nOPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\n\r\n", true},
		{"header without colon", "OPTIONS sip:x SIP/2.0\r\nCall-ID c\r\n\r\n", true},
		{"first header folded without colon", "OPTIONS sip:x SIP/2.0\r\n no colon\r\n\r\n", true},
		{"second header without colon", "OPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\nbroken\r\n\r\n", true},
		{"folded header never has a colon", "OPTIONS sip:x SIP/2.0\r\nSubject\r\n  more\r\nCall-ID: c\r\n\r\n", true},
		{"binary", "\x01\x02\x03\xff\xfe", true},
	}
	for _, c := range cases {
		if got := Malformed([]byte(c.in)); got != c.want {
			t.Errorf("%s: Malformed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMalformedDoesNotAllocate(t *testing.T) {
	data := []byte(okInvite)
	if n := testing.AllocsPerRun(100, func() { Malformed(data) }); n != 0 {
		t.Errorf("allocs = %v, want 0", n)
	}
}
