package trunk

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/media"
)

const (
	auditSentinelIP   = "198.51.100.77"
	auditSentinelPort = "31337"
	auditSentinelUser = "sentinelorigin"
)

// auditRandomSDP builds a random, well-formed SDP whose topology fields
// (c=, o=, m= port) always carry the sentinel, plus the sentinel in one
// extra place chosen by kind ("base" adds nothing: it checks that the
// fields the bridge claims to rewrite are in fact rewritten). Every other field is randomized.
func auditRandomSDP(r *rand.Rand, kind string) string {
	codecs := [][2]string{{"0", "PCMU/8000"}, {"8", "PCMA/8000"}, {"9", "G722/8000"}, {"18", "G729/8000"}, {"101", "telephone-event/8000"}}
	r.Shuffle(len(codecs), func(i, j int) { codecs[i], codecs[j] = codecs[j], codecs[i] })
	n := 1 + r.Intn(len(codecs))
	var pts []string
	var rtpmaps []string
	for _, c := range codecs[:n] {
		pts = append(pts, c[0])
		rtpmaps = append(rtpmaps, "a=rtpmap:"+c[0]+" "+c[1])
	}
	sessID := 1000 + r.Intn(1_000_000)
	var b strings.Builder
	b.WriteString("v=0\r\n")
	user := fmt.Sprintf("u%d", r.Intn(1000))
	if kind == "origin-user" {
		user = auditSentinelUser
	}
	fmt.Fprintf(&b, "o=%s %d %d IN IP4 %s\r\n", user, sessID, sessID, auditSentinelIP)
	fmt.Fprintf(&b, "s=call%d\r\n", r.Intn(1000))
	fmt.Fprintf(&b, "c=IN IP4 %s\r\n", auditSentinelIP)
	b.WriteString("t=0 0\r\n")
	if kind == "session-attr" {
		fmt.Fprintf(&b, "a=x-peer-addr:%s:%s\r\n", auditSentinelIP, auditSentinelPort)
	}
	// Optional leading video section (declined by the bridge).
	if r.Intn(2) == 0 {
		fmt.Fprintf(&b, "m=video %d RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n", 20000+2*r.Intn(1000))
	}
	fmt.Fprintf(&b, "m=audio %s RTP/AVP %s\r\n", auditSentinelPort, strings.Join(pts, " "))
	if r.Intn(2) == 0 {
		fmt.Fprintf(&b, "c=IN IP4 %s\r\n", auditSentinelIP)
	}
	for _, l := range rtpmaps {
		b.WriteString(l + "\r\n")
	}
	if r.Intn(2) == 0 {
		fmt.Fprintf(&b, "a=ptime:%d\r\n", []int{10, 20, 30}[r.Intn(3)])
	}
	b.WriteString([]string{"a=sendrecv\r\n", "a=sendonly\r\n", "a=recvonly\r\n"}[r.Intn(3)])
	switch kind {
	case "rtcp":
		fmt.Fprintf(&b, "a=rtcp:%s IN IP4 %s\r\n", auditSentinelPort, auditSentinelIP)
	case "candidate":
		fmt.Fprintf(&b, "a=candidate:1 1 UDP 2130706431 %s %s typ host\r\n", auditSentinelIP, auditSentinelPort)
		fmt.Fprintf(&b, "a=candidate:2 1 UDP 1694498815 203.0.113.%d %d typ srflx raddr %s rport %s\r\n",
			1+r.Intn(250), 30000+r.Intn(1000), auditSentinelIP, auditSentinelPort)
	case "remote-candidates":
		fmt.Fprintf(&b, "a=remote-candidates:1 %s %s\r\n", auditSentinelIP, auditSentinelPort)
	case "ice":
		fmt.Fprintf(&b, "a=ice-ufrag:%s\r\na=ice-pwd:%s%s\r\n", auditSentinelUser, auditSentinelUser, "pwdpwdpwdpwdpwd")
		fmt.Fprintf(&b, "a=fingerprint:sha-256 %s\r\na=setup:actpass\r\n", strings.Repeat("AB:", 31)+"AB")
	case "ssrc":
		fmt.Fprintf(&b, "a=ssrc:%d cname:%s@%s\r\n", r.Uint32(), "cn", auditSentinelIP)
	case "fmtp":
		fmt.Fprintf(&b, "a=fmtp:101 0-15;x-host=%s\r\n", auditSentinelIP)
	}
	// Optional trailing declined section carrying its own address. (m=image
	// is not used here: pion/sdp v3.0.19 rejects it outright — see
	// TestAuditT38ImageSectionAccepted.)
	if r.Intn(2) == 0 {
		fmt.Fprintf(&b, "m=application %d UDP/BFCP *\r\nc=IN IP4 %s\r\n", 40000+r.Intn(1000), auditSentinelIP)
	}
	return b.String()
}

// audit: P2-TRK-006
// Property: whatever the carrier/PBX leg's SDP carries, the SDP the bridge
// relays to the other leg (rewriteSDPCrypto, used for the B-leg offer, the
// A-leg answer and early media) never contains an address, port or origin
// identity learned from that leg. docs/trunk.md:65-66 promises "full SDP
// rewrite" with topology hiding.
func TestAuditSDPLeakProperty(t *testing.T) {
	seed := time.Now().UnixNano()
	t.Logf("seed=%d", seed)
	kinds := []string{"base", "origin-user", "rtcp", "candidate", "remote-candidates", "ice", "ssrc", "fmtp", "session-attr"}
	ourIP := netip.MustParseAddr("192.0.2.10")
	const ourPort = 40000
	for _, kind := range kinds {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			r := rand.New(rand.NewSource(seed))
			for i := 0; i < 300; i++ {
				in := auditRandomSDP(r, kind)
				for _, secure := range []bool{false, true} {
					var crypto *sdpCrypto
					if secure {
						suite, _ := media.ParseCryptoSuite("AES_CM_128_HMAC_SHA1_80")
						crypto = &sdpCrypto{suite: suite, keyValue: make([]byte, media.SDESKeyLen), tag: 1}
					}
					out, err := rewriteSDPCrypto([]byte(in), ourIP, ourPort, crypto)
					if err != nil {
						t.Fatalf("iteration %d: rewrite error %v\ninput:\n%s", i, err, in)
					}
					for _, sentinel := range []string{auditSentinelIP, auditSentinelPort, auditSentinelUser} {
						if strings.Contains(string(out), sentinel) {
							var leaked []string
							for _, l := range strings.Split(string(out), "\r\n") {
								if strings.Contains(l, sentinel) {
									leaked = append(leaked, l)
								}
							}
							t.Fatalf("iteration %d (secure=%v): sentinel %q from the other leg appears in relayed SDP: %q\ninput:\n%s\noutput:\n%s",
								i, secure, sentinel, leaked, in, out)
						}
					}
				}
			}
		})
	}
}
