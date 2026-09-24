package trunk

import (
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/emiago/sipgo/sip"
	"github.com/freesbc/freesbc/internal/media"
	"github.com/pion/sdp/v3"
)

// Fuzz targets for trunk-local parsers that consume peer-controlled bytes.
// Run each with: go test ./internal/trunk -run '^$' -fuzz '^FuzzAuditX$' -fuzztime=60s
// A crash (panic) is a P0 finding. Known non-crash defects in these
// parsers are covered by the unit tests in audit_units_test.go, so the
// targets below only assert properties those tests do not already cover.

// audit: P2-TRK-011
func FuzzAuditChallengeRealm(f *testing.F) {
	for _, s := range []string{
		`Digest realm="carrier", nonce="n"`,
		`Digest xrealm="trusted", realm="rogue", nonce="n"`,
		`Digest realm='x'`,
		`Digest realm=`,
		`Digest realm="`,
		`realm=a,b`,
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, v string, proxy bool) {
		code, name := 401, "WWW-Authenticate"
		if proxy {
			code, name = 407, "Proxy-Authenticate"
		}
		res := sip.NewResponse(code, "x")
		res.AppendHeader(sip.NewHeader(name, v))
		_ = challengeRealm(res)
	})
}

// audit: P2-TRK-010, P2-TRK-018
// Parses the whole request off the wire first (as the transport does) and
// then runs every trunk header helper that reads it.
func FuzzAuditSIPHeaderHelpers(f *testing.F) {
	f.Add([]byte(auditInviteWithHeaders("Session-Expires: 1800;refresher=uac", "Min-SE: 90")))
	f.Add([]byte(auditInviteWithHeaders("x: 30", "Require: 100rel, timer")))
	f.Add([]byte(auditInviteWithHeaders("Session-Expires: 9223372036854775807;refresher=")))
	f.Fuzz(func(t *testing.T, raw []byte) {
		msg, err := sip.ParseMessage(raw)
		if err != nil {
			return
		}
		req, ok := msg.(*sip.Request)
		if !ok {
			return
		}
		_ = headerSeconds(req, "Session-Expires")
		_ = headerSeconds(req, "Min-SE")
		_ = requires100rel(req)
		_ = refresherOf(req)
		_ = isRefreshReInvite(req, req.Body())
	})
}

// audit: P2-TRK-012
func FuzzAuditParseCryptoAttrs(f *testing.F) {
	key := base64.StdEncoding.EncodeToString(make([]byte, media.SDESKeyLen))
	f.Add("1 AES_CM_128_HMAC_SHA1_80 inline:" + key)
	f.Add("1 AES_CM_128_HMAC_SHA1_32 inline:" + key + "|2^20|1:4")
	f.Add("2 AES_CM_128_HMAC_SHA1_80 inline:" + key + " UNENCRYPTED_SRTP")
	f.Add("x y inline:")
	f.Fuzz(func(t *testing.T, v string) {
		for _, l := range parseCryptoAttrs([]string{v}) {
			if len(l.keyValue) != media.SDESKeyLen {
				t.Fatalf("accepted key of length %d", len(l.keyValue))
			}
		}
	})
}

// audit: P2-TRK-006, P2-TRK-022
// Every SDP helper on the trunk's peer-body path. Property: when the rewrite
// succeeds, its output must itself be a relayable SDP pointing at our
// address (the other leg will parse it with the same rules).
func FuzzAuditTrunkSDP(f *testing.F) {
	key := base64.StdEncoding.EncodeToString(make([]byte, media.SDESKeyLen))
	f.Add(testSDPBody(4000), false)
	f.Add([]byte("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n"+
		"m=video 5000 RTP/AVP 96\r\nm=audio 4000 RTP/SAVP 0\r\na=rtcp:4001 IN IP4 192.0.2.1\r\n"+
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"+key+"|2^20|1:4\r\n"), true)
	f.Add([]byte("v=0\r\no=- 1 1 IN IP6 ::1\r\ns=-\r\nc=IN IP6 ::1\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\nm=audio 7 RTP/AVP 0\r\n"), false)
	ourIP := netip.MustParseAddr("192.0.2.10")
	suite, _ := media.ParseCryptoSuite("AES_CM_128_HMAC_SHA1_80")
	f.Fuzz(func(t *testing.T, body []byte, secure bool) {
		_ = validAudioSDP(body)
		_, _ = remoteMediaIP(body)
		_, _ = offeredCrypto(body)
		var crypto *sdpCrypto
		if secure {
			crypto = &sdpCrypto{suite: suite, keyValue: make([]byte, media.SDESKeyLen), tag: 1}
		}
		out, err := rewriteSDPCrypto(body, ourIP, 40000, crypto)
		if err != nil {
			return
		}
		if err := validAudioSDP(out); err != nil {
			t.Fatalf("rewrite output is not relayable: %v\nin:\n%q\nout:\n%q", err, body, out)
		}
		ip, err := remoteMediaIP(out)
		if err != nil {
			t.Fatalf("rewrite output has no usable media address: %v\nin:\n%q\nout:\n%q", err, body, out)
		}
		if ip != ourIP {
			t.Fatalf("rewrite output points media at %v, want %v\nin:\n%q\nout:\n%q", ip, ourIP, body, out)
		}
		if !secure {
			var sd sdp.SessionDescription
			if err := sd.Unmarshal(out); err != nil {
				t.Fatalf("rewrite output does not re-parse: %v\nout:\n%q", err, out)
			}
			keys := 0
			for _, a := range sd.Attributes {
				if a.Key == "crypto" {
					keys++
				}
			}
			for _, md := range sd.MediaDescriptions {
				for _, a := range md.Attributes {
					if a.Key == "crypto" {
						keys++
					}
				}
			}
			if keys > 0 {
				t.Fatalf("plaintext rewrite still carries %d a=crypto attribute(s)\nin:\n%q\nout:\n%q", keys, body, out)
			}
		}
	})
}
