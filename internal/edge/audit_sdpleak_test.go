package edge

// Phase 3 SDP leak property test (docs/audit). The edge must build every
// SDP body from scratch: nothing learned from one leg's SDP (addresses,
// ports, free text) may appear in the body it sends to the other leg
// (docs/edge.md:65 "constructed, never derived"; CLAUDE.md topology
// hiding). Each leg's SDP is seeded with sentinel values in c=, o=, m= port,
// a=rtcp, a=candidate, a=fmtp, a=tool and a video section, while codecs,
// payload-type numbers, section order, direction and extra attributes are
// randomised. The sentinel must never cross.

import (
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// auditSentinels are the values seeded into one leg's SDP. origin 91 marks
// the public leg (phone/browser), 92 the private leg (FreeSWITCH).
type auditSentinels struct {
	origin int
	fields map[string]string // field name → sentinel token
}

func auditNewSentinels(origin int) auditSentinels {
	base := 59000 + origin*10 // 59910.. for public, 59920.. for private
	return auditSentinels{origin: origin, fields: map[string]string{
		"c= address":         fmt.Sprintf("10.%d.0.1", origin),
		"o= address":         fmt.Sprintf("10.%d.0.2", origin),
		"a=rtcp address":     fmt.Sprintf("10.%d.0.3", origin),
		"a=candidate addr":   fmt.Sprintf("10.%d.0.4", origin),
		"a=fmtp text":        fmt.Sprintf("10.%d.0.5", origin),
		"video c= address":   fmt.Sprintf("10.%d.0.6", origin),
		"a=tool text":        fmt.Sprintf("10.%d.0.7", origin),
		"m= audio port":      fmt.Sprint(base),
		"a=rtcp port":        fmt.Sprint(base + 1),
		"a=candidate port":   fmt.Sprint(base + 2),
		"m= video port":      fmt.Sprint(base + 3),
		"a=fmtp port text":   fmt.Sprint(base + 4),
		"o= username":        fmt.Sprintf("leakuser%d", origin),
		"a=candidate foundn": fmt.Sprintf("leakfnd%d", origin),
	}}
}

func (s auditSentinels) get(f string) string { return s.fields[f] }

// auditLeaks returns the sentinel fields whose token appears in body. Tokens
// are matched on non-alphanumeric boundaries so "59910" does not match
// inside a longer number (the o= session id is a nanosecond clock).
func auditLeaks(body string, s auditSentinels) []string {
	var out []string
	for f, tok := range s.fields {
		re := regexp.MustCompile(`(^|[^0-9A-Za-z.])` + regexp.QuoteMeta(tok) + `($|[^0-9A-Za-z])`)
		if re.MatchString(body) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

type auditCodec struct {
	pt     int
	rtpmap string
	fmtp   string
}

// auditRandomCodecs is a random, shuffled codec list that always contains
// PCMU (so every offer is relayable) and telephone-event with a random
// dynamic payload type and a sentinel in its fmtp.
func auditRandomCodecs(r *rand.Rand, s auditSentinels) []auditCodec {
	tePT := 96 + r.Intn(16)
	opusPT := 112 + r.Intn(16)
	list := []auditCodec{{pt: 0, rtpmap: "PCMU/8000"}}
	if r.Intn(2) == 0 {
		list = append(list, auditCodec{pt: 8, rtpmap: "PCMA/8000"})
	}
	if r.Intn(2) == 0 {
		list = append(list, auditCodec{pt: 9, rtpmap: "G722/8000"})
	}
	if r.Intn(2) == 0 {
		list = append(list, auditCodec{pt: opusPT, rtpmap: "opus/48000/2", fmtp: "minptime=10;useinbandfec=1"})
	}
	r.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
	te := auditCodec{pt: tePT, rtpmap: "telephone-event/8000",
		fmtp: fmt.Sprintf("0-16;x=%s;p=%s", s.get("a=fmtp text"), s.get("a=fmtp port text"))}
	at := r.Intn(len(list) + 1)
	list = append(list[:at], append([]auditCodec{te}, list[at:]...)...)
	return list
}

// auditBuildSDP renders one body with every sentinel in place. video: -1 no
// video section, 0 before the audio section, 1 after it.
func auditBuildSDP(r *rand.Rand, s auditSentinels, codecs []auditCodec, dir string, video int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "v=0\r\no=%s %d %d IN IP4 %s\r\ns=-\r\n", s.get("o= username"), r.Int63n(1e9), 1+r.Intn(5), s.get("o= address"))
	fmt.Fprintf(&b, "c=IN IP4 %s\r\nt=0 0\r\n", s.get("c= address"))
	if r.Intn(2) == 0 {
		fmt.Fprintf(&b, "a=tool:%s\r\n", s.get("a=tool text"))
	}
	videoSec := fmt.Sprintf("m=video %s RTP/AVP 97\r\nc=IN IP4 %s\r\na=rtpmap:97 VP8/90000\r\n",
		s.get("m= video port"), s.get("video c= address"))
	if video == 0 {
		b.WriteString(videoSec)
	}
	pts := make([]string, len(codecs))
	for i, c := range codecs {
		pts[i] = fmt.Sprint(c.pt)
	}
	fmt.Fprintf(&b, "m=audio %s RTP/AVP %s\r\n", s.get("m= audio port"), strings.Join(pts, " "))
	fmt.Fprintf(&b, "a=rtcp:%s IN IP4 %s\r\n", s.get("a=rtcp port"), s.get("a=rtcp address"))
	fmt.Fprintf(&b, "a=candidate:%s 1 UDP 2130706431 %s %s typ host\r\n",
		s.get("a=candidate foundn"), s.get("a=candidate addr"), s.get("a=candidate port"))
	extras := []string{"a=ptime:20", "a=maxptime:40", "a=label:1", "a=x-custom:hello"}
	r.Shuffle(len(extras), func(i, j int) { extras[i], extras[j] = extras[j], extras[i] })
	for _, c := range codecs {
		fmt.Fprintf(&b, "a=rtpmap:%d %s\r\n", c.pt, c.rtpmap)
		if c.fmtp != "" {
			fmt.Fprintf(&b, "a=fmtp:%d %s\r\n", c.pt, c.fmtp)
		}
	}
	for _, e := range extras[:r.Intn(len(extras)+1)] {
		b.WriteString(e + "\r\n")
	}
	fmt.Fprintf(&b, "a=%s\r\n", dir)
	if video == 1 {
		b.WriteString(videoSec)
	}
	return b.String()
}

func auditRandomOffer(r *rand.Rand, s auditSentinels) string {
	dirs := []string{"sendrecv", "sendrecv", "sendonly", "recvonly"}
	return auditBuildSDP(r, s, auditRandomCodecs(r, s), dirs[r.Intn(len(dirs))], r.Intn(3)-1)
}

// auditSentinelAnswer answers the offer the edge built: the offer's first
// media codec and its telephone-event (same payload numbers, RFC 3264 §6),
// with every sentinel seeded.
func auditSentinelAnswer(r *rand.Rand, s auditSentinels, offerBody []byte) string {
	off, err := parseLabSDP(offerBody)
	if err != nil || off.Audio == nil {
		return auditBuildSDP(r, s, []auditCodec{{pt: 0, rtpmap: "PCMU/8000"}}, "sendrecv", -1)
	}
	var codecs []auditCodec
	haveMedia := false
	for _, c := range off.Audio.Codecs {
		name := strings.ToLower(c.Name)
		rtpmap := fmt.Sprintf("%s/%d", c.Name, c.ClockRate)
		if c.Channels > 0 {
			rtpmap += fmt.Sprintf("/%d", c.Channels)
		}
		switch {
		case name == "telephone-event":
			codecs = append(codecs, auditCodec{pt: int(c.PayloadType), rtpmap: rtpmap,
				fmtp: fmt.Sprintf("0-16;x=%s;p=%s", s.get("a=fmtp text"), s.get("a=fmtp port text"))})
		case !haveMedia:
			haveMedia = true
			codecs = append(codecs, auditCodec{pt: int(c.PayloadType), rtpmap: rtpmap, fmtp: c.FMTP})
		}
	}
	dir := "sendrecv"
	switch off.Audio.Direction {
	case sdp.SendOnly:
		dir = "recvonly"
	case sdp.RecvOnly:
		dir = "sendonly"
	}
	return auditBuildSDP(r, s, codecs, dir, -1)
}

// auditHookRand gives each hook invocation its own generator derived from
// the test seed: sipgo runs hooks on their own goroutines, and a shared
// *rand.Rand is not safe for concurrent use.
var auditHookSeq atomic.Int64

func auditHookRand(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed + 1_000_003*auditHookSeq.Add(1)))
}

// auditLeakLog accumulates leaks per direction and field.
type auditLeakLog struct {
	counts  map[string]int
	samples map[string]string
	checks  map[string]int
}

func newAuditLeakLog() *auditLeakLog {
	return &auditLeakLog{counts: map[string]int{}, samples: map[string]string{}, checks: map[string]int{}}
}

func (l *auditLeakLog) check(direction string, body []byte, s auditSentinels) {
	l.checks[direction]++
	for _, f := range auditLeaks(string(body), s) {
		k := direction + " | " + f
		l.counts[k]++
		if _, ok := l.samples[k]; !ok {
			l.samples[k] = string(body)
		}
	}
}

func (l *auditLeakLog) report(t *testing.T) {
	t.Helper()
	keys := make([]string, 0, len(l.counts))
	for k := range l.counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for d, n := range l.checks {
		t.Logf("checked %d bodies: %s", n, d)
	}
	for _, k := range keys {
		t.Errorf("P2-EDG-030/P2-SDP-003 leak: %s — %d times; first body:\n%s", k, l.counts[k], l.samples[k])
	}
}

// audit: P2-EDG-030
// audit: P2-SDP-003
func TestAuditSDPLeakProperty(t *testing.T) {
	seed := time.Now().UnixNano()
	t.Logf("seed %d", seed)
	r := rand.New(rand.NewSource(seed))
	pub, priv := auditNewSentinels(91), auditNewSentinels(92)
	log := newAuditLeakLog()

	// A: phone → FreeSWITCH, offer and answer; C: phone re-INVITE, both ways.
	t.Run("phone-initiated", func(t *testing.T) {
		h := startHarness(t, false)
		h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
			body := auditSentinelAnswer(auditHookRand(seed), priv, req.Body())
			res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
			if _, ok := req.To().Params.Get("tag"); !ok {
				res.To().Params.Add("tag", sip.GenerateTagN(12))
			}
			_ = tx.Respond(res)
			return true
		})
		for i := 0; i < 30; i++ {
			phone := newUDPClient(t)
			offer := auditRandomOffer(r, pub)
			invite := phone.buildInvite("1001", "2002", "example.com", offer)
			seen := len(h.fs.received(sip.INVITE))
			res := phone.do(t, invite, h.publicUDP)
			ups := h.fs.waitFor(sip.INVITE, seen+1, 3*time.Second)
			if len(ups) > seen {
				log.check("public offer → FreeSWITCH INVITE", ups[seen].Body(), pub)
			}
			if res.StatusCode != 200 {
				t.Logf("iteration %d: INVITE %d (offer not relayable)\n%s", i, res.StatusCode, offer)
				phone.cancel()
				continue
			}
			log.check("FreeSWITCH answer → phone 200", res.Body(), priv)
			sendAck(t, phone, invite, res, h.publicUDP)
			waitForDialog(t, h, fsip.CallID(invite))
			if i%3 == 0 {
				seen = len(h.fs.received(sip.INVITE))
				_, reRes := auditPhoneReInvite(t, h, phone, invite, res, 2, auditRandomOffer(r, pub))
				if ups := h.fs.waitFor(sip.INVITE, seen+1, 3*time.Second); len(ups) > seen {
					log.check("public re-offer → FreeSWITCH re-INVITE", ups[seen].Body(), pub)
				}
				if reRes.StatusCode == 200 {
					log.check("FreeSWITCH re-answer → phone 200", reRes.Body(), priv)
				}
			}
			phone.do(t, buildBye(phone, invite, res), h.publicUDP)
			phone.cancel()
		}
	})

	// B: FreeSWITCH → registered phone, offer and answer.
	t.Run("switch-initiated", func(t *testing.T) {
		h := startHarness(t, false)
		phone := newUDPClient(t)
		ruri := auditRegisterPhone(t, h, phone, "1001")
		auditPhoneAnswers(phone, 0, func(req *sip.Request) string {
			return auditSentinelAnswer(auditHookRand(seed), pub, req.Body())
		})
		for i := 0; i < 15; i++ {
			drain(phone.inbound)
			res := h.fs.call(t, ruri, h.privateSIP, auditRandomOffer(r, priv))
			select {
			case got := <-phone.inbound:
				if got.Method == sip.INVITE {
					log.check("FreeSWITCH offer → phone INVITE", got.Body(), priv)
				}
			case <-time.After(2 * time.Second):
			}
			if res.StatusCode != 200 {
				t.Logf("iteration %d: inbound INVITE %d", i, res.StatusCode)
				continue
			}
			log.check("phone answer → FreeSWITCH 200", res.Body(), pub)
			waitForDialog(t, h, fsip.CallID(res))
			h.fs.sendAckTo2xx(t, res)
			h.fs.uacBye(t, res)
		}
	})

	// D: browser (WebRTC) offer → FreeSWITCH.
	t.Run("browser-initiated", func(t *testing.T) {
		h := startHarness(t, true)
		for i := 0; i < 10; i++ {
			browser := newWSClient(t)
			offer := browserOfferSDP(0)
			offer = strings.Replace(offer, "m=audio 0 ", "m=audio "+pub.get("m= audio port")+" ", 1)
			offer = strings.Replace(offer, "c=IN IP4 192.168.44.44", "c=IN IP4 "+pub.get("c= address"), 1)
			offer = strings.Replace(offer, "a=rtcp:1 IN IP4 192.168.44.44",
				"a=rtcp:"+pub.get("a=rtcp port")+" IN IP4 "+pub.get("a=rtcp address"), 1)
			offer = strings.ReplaceAll(offer, "192.168.44.44", pub.get("a=candidate addr"))
			offer = strings.ReplaceAll(offer, "203.0.113.99", pub.get("a=candidate addr"))
			offer = strings.ReplaceAll(offer, " 0 typ host", " "+pub.get("a=candidate port")+" typ host")
			offer = strings.Replace(offer, "useinbandfec=1", "useinbandfec=1;x="+pub.get("a=fmtp text"), 1)
			offer = strings.Replace(offer, "o=- ", "o="+pub.get("o= username")+" ", 1)
			invite := browser.buildInvite("1001", "2002", "example.com", offer)
			seen := len(h.fs.received(sip.INVITE))
			res := browser.do(t, invite, h.publicWS)
			if ups := h.fs.waitFor(sip.INVITE, seen+1, 3*time.Second); len(ups) > seen {
				log.check("browser offer → FreeSWITCH INVITE", ups[seen].Body(), pub)
			}
			if res.StatusCode == 200 {
				sendAck(t, browser, invite, res, h.publicWS)
				browser.do(t, buildBye(browser, invite, res), h.publicWS)
			}
			browser.cancel()
		}
	})

	log.report(t)
}
