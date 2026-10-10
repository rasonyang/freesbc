package sdp

import (
	"net/netip"
	"strings"
	"testing"
)

// Micro-benchmarks for SDP parse and build (issue #109). They run only
// under -bench.

const benchFP = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"

var benchOffers = []struct{ name, body string }{
	{"plain", strings.Join([]string{
		"v=0",
		"o=- 3921034 3921034 IN IP4 203.0.113.50",
		"s=-",
		"c=IN IP4 203.0.113.50",
		"t=0 0",
		"m=audio 40000 RTP/AVP 0 8 9 101",
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:8 PCMA/8000",
		"a=rtpmap:9 G722/8000",
		"a=rtpmap:101 telephone-event/8000",
		"a=fmtp:101 0-16",
		"a=ptime:20",
		"a=sendrecv",
		"",
	}, "\r\n")},
	{"sdes", strings.Join([]string{
		"v=0",
		"o=- 3921034 3921034 IN IP4 203.0.113.50",
		"s=-",
		"c=IN IP4 203.0.113.50",
		"t=0 0",
		"m=audio 40000 RTP/SAVP 0 8 101",
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:8 PCMA/8000",
		"a=rtpmap:101 telephone-event/8000",
		"a=fmtp:101 0-16",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
		"a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
		"a=ptime:20",
		"a=sendrecv",
		"",
	}, "\r\n")},
	{"webrtc", strings.Join([]string{
		"v=0",
		"o=- 4611731400430051336 2 IN IP4 127.0.0.1",
		"s=-",
		"t=0 0",
		"a=group:BUNDLE 0",
		"a=msid-semantic: WMS",
		"m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 110 126",
		"c=IN IP4 192.0.2.10",
		"a=rtcp:9 IN IP4 0.0.0.0",
		"a=ice-ufrag:4ZcD",
		"a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkw",
		"a=ice-options:trickle",
		"a=fingerprint:sha-256 " + benchFP,
		"a=setup:actpass",
		"a=mid:0",
		"a=sendrecv",
		"a=rtcp-mux",
		"a=rtpmap:111 opus/48000/2",
		"a=rtcp-fb:111 transport-cc",
		"a=fmtp:111 minptime=10;useinbandfec=1",
		"a=rtpmap:63 red/48000/2",
		"a=rtpmap:9 G722/8000",
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:8 PCMA/8000",
		"a=rtpmap:110 telephone-event/48000",
		"a=rtpmap:126 telephone-event/8000",
		"a=candidate:1 1 udp 2113937151 192.0.2.10 54321 typ host",
		"",
	}, "\r\n")},
}

func BenchmarkParse(b *testing.B) {
	for _, o := range benchOffers {
		b.Run(o.name, func(b *testing.B) {
			body := []byte(o.body)
			s, err := Parse(body)
			if err != nil {
				b.Fatal(err)
			}
			switch o.name {
			case "sdes":
				if !s.Audio.SDES() || len(s.Audio.Crypto) == 0 {
					b.Fatal("sdes offer not parsed as SDES")
				}
			case "webrtc":
				if !s.Audio.WebRTC() {
					b.Fatal("webrtc offer not parsed as WebRTC")
				}
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Parse(body); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchBuilds(b *testing.B) map[string]Build {
	b.Helper()
	addr := netip.MustParseAddr("198.51.100.7")
	pcmu := Codec{PayloadType: 0, Name: "PCMU", ClockRate: 8000}
	pcma := Codec{PayloadType: 8, Name: "PCMA", ClockRate: 8000}
	te := Codec{PayloadType: 101, Name: "telephone-event", ClockRate: 8000, FMTP: "0-16"}
	opus := Codec{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2, FMTP: "minptime=10;useinbandfec=1"}
	crypto, err := OfferCrypto(SupportedSuites[0])
	if err != nil {
		b.Fatal(err)
	}
	return map[string]Build{
		"plain": {Address: addr, Port: 20000, Codecs: []Codec{pcmu, pcma, te}, Direction: SendRecv, SessionID: 1, SessionVersion: 1},
		"sdes":  {Address: addr, Port: 20000, Codecs: []Codec{pcmu, pcma, te}, Direction: SendRecv, SessionID: 1, SessionVersion: 1, Crypto: crypto},
		"webrtc": {
			Address: addr, Port: 20000, Codecs: []Codec{opus, pcmu, te}, Direction: SendRecv, SessionID: 1, SessionVersion: 1,
			DTLS: true, RTCPMux: true, ICEUfrag: "abcd", ICEPwd: "0123456789abcdef01234567",
			Fingerprint: &Fingerprint{Hash: "sha-256", Value: benchFP}, Setup: "passive",
		},
	}
}

func BenchmarkBuildMarshal(b *testing.B) {
	builds := benchBuilds(b)
	for _, name := range []string{"plain", "sdes", "webrtc"} {
		bld := builds[name]
		b.Run(name, func(b *testing.B) {
			out, err := bld.Marshal()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(out)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := bld.Marshal(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
