package sdp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Equivalence tests for the allocation work of issue #173: Build's
// append-based writer, Negotiate's in-place codec matching and the
// stack-buffered canonicalFMTP must produce exactly what the
// implementations they replaced produced (kept in build_ref_test.go,
// fmtp_ref_test.go and below), for every input, errors included.

// negotiateRef is Negotiate before issue #173, verbatim but for names.
func negotiateRef(offer, answer []Codec) ([]Codec, error) {
	offered := make(map[string]bool, len(offer))
	offeredAt := make(map[ptKeyRef]bool, len(offer))
	for _, o := range offer {
		offered[keyRef(o)] = true
		offeredAt[ptKeyRef{o.PayloadType, keyRef(o)}] = true
	}
	byPT := make(map[uint8]Codec, len(answer))
	for _, a := range answer {
		if offeredAt[ptKeyRef{a.PayloadType, keyRef(a)}] {
			if _, dup := byPT[a.PayloadType]; !dup {
				byPT[a.PayloadType] = a
			}
			continue
		}
		if offered[keyRef(a)] {
			return nil, fmt.Errorf("%w: offered %s, answered %s", ErrRenumbered, Describe(offerOfRef(offer, keyRef(a))), a)
		}
	}
	var out []Codec
	for _, o := range offer {
		a, ok := byPT[o.PayloadType]
		if !ok || keyRef(a) != keyRef(o) {
			continue
		}
		merged := o
		merged.FMTP = a.FMTP
		out = append(out, merged)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: offer %s vs answer %s", ErrNoCommonCodec, Describe(offer), Describe(answer))
	}
	if !HasMedia(out) {
		return nil, fmt.Errorf("%w: only telephone-event in common", ErrNoCommonCodec)
	}
	return out, nil
}

type ptKeyRef struct {
	pt  uint8
	key string
}

func keyRef(c Codec) string {
	ch := c.Channels
	if ch == 0 {
		ch = 1
	}
	return fmt.Sprintf("%s/%d/%d", strings.ToLower(c.Name), c.ClockRate, ch)
}

func offerOfRef(offer []Codec, key string) []Codec {
	var out []Codec
	for _, o := range offer {
		if keyRef(o) == key {
			out = append(out, o)
		}
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// Codec names that exercise sameName: case variants, a name with '/',
// and non-ASCII names whose ToLower differs from simple case folding
// (Kelvin sign, long s, dotted capital I) or is not valid UTF-8.
var equivNames = []string{
	"PCMU", "pcmu", "PcMu", "PCMA", "G722", "g722", "opus", "OPUS", "red",
	"telephone-event", "Telephone-Event", "TELEPHONE-EVENT",
	"AMR", "amr", "AMR-WB", "amr-wb", "G729", "iLBC", "ILBC", "G7221",
	"x/8000", "", "\u212A", "k", "K", "\u017F", "s", "S", "\u0130", "i\u0307", "\xff", "\xfe", "pcm\u00dc",
}

var equivFMTP = []string{
	"", "0-16", "0-15,66,70", "00-016", "+1-2", "16-0", "0-16;foo=bar", "foo=bar;0-15", " 0 - 16 ",
	strings.Repeat("1,", 63) + "1", strings.Repeat("1,", 64) + "1", "256", "1-256",
	"minptime=10;useinbandfec=1", "MINPTIME=010; useinbandfec=1;foo=bar", "minptime=10;minptime=20",
	"maxaveragebitrate=20000", "maxaveragebitrate=0020000", "maxaveragebitrate=0", "maxplaybac\u212Arate=8000",
	"stereo=1;sprop-stereo=0;cbr=1;usedtx=0;maxptime=120;ptime=20;maxplaybackrate=48000;sprop-maxcapturerate=16000",
	"mode-set=0,2,5,7;octet-align=1", "mode-set=+0, 2;crc=1", "mode-set=9", "annexb=YES", "annexb=ye\u017F",
	"mode=30", "bitrate=24000", "garbage", ";;;", "=;=", strings.Repeat("a", maxFMTP+1),
	"useinbandfec=1;" + strings.Repeat(" ", 400),
}

func randCodec(r *rand.Rand) Codec {
	pts := []uint8{0, 8, 9, 18, 96, 97, 101, 110, 111, 126, 127, 200, 255}
	rates := []uint32{0, 8000, 16000, 48000, 4294967295}
	chans := []int{-1, 0, 0, 1, 1, 2, 8, 100}
	return Codec{
		PayloadType: pts[r.IntN(len(pts))],
		Name:        equivNames[r.IntN(len(equivNames))],
		ClockRate:   rates[r.IntN(len(rates))],
		Channels:    chans[r.IntN(len(chans))],
		FMTP:        equivFMTP[r.IntN(len(equivFMTP))],
	}
}

func randCodecs(r *rand.Rand, max int) []Codec {
	n := r.IntN(max + 1)
	if n == 0 && r.IntN(2) == 0 {
		return nil
	}
	out := make([]Codec, n)
	for i := range out {
		out[i] = randCodec(r)
	}
	return out
}

func TestNegotiateMatchesReference(t *testing.T) {
	r := rand.New(rand.NewPCG(173, 1))
	for i := 0; i < 50000; i++ {
		offer := randCodecs(r, 8)
		var answer []Codec
		switch r.IntN(3) {
		case 0:
			answer = randCodecs(r, 8)
		default:
			// Mostly drawn from the offer, so matches and renumbers are
			// common rather than rare.
			for _, o := range offer {
				if r.IntN(3) == 0 {
					continue
				}
				a := o
				if r.IntN(6) == 0 {
					a.PayloadType = uint8(r.IntN(256))
				}
				if r.IntN(6) == 0 {
					a.Name = strings.ToUpper(a.Name)
				}
				a.FMTP = equivFMTP[r.IntN(len(equivFMTP))]
				answer = append(answer, a)
			}
			r.Shuffle(len(answer), func(i, j int) { answer[i], answer[j] = answer[j], answer[i] })
		}
		got, gerr := Negotiate(offer, answer)
		want, werr := negotiateRef(offer, answer)
		if errText(gerr) != errText(werr) || !reflect.DeepEqual(got, want) {
			t.Fatalf("Negotiate(%#v, %#v):\n got %#v, %v\nwant %#v, %v", offer, answer, got, gerr, want, werr)
		}
	}
}

func TestSameNameMatchesToLower(t *testing.T) {
	for _, a := range equivNames {
		for _, b := range equivNames {
			if got, want := sameName(a, b), strings.ToLower(a) == strings.ToLower(b); got != want {
				t.Errorf("sameName(%q, %q) = %v, want %v", a, b, got, want)
			}
		}
	}
}

func TestCanonicalFMTPMatchesReference(t *testing.T) {
	names := append([]string{"opus", "Opus", "amr", "AMR-WB", "g729", "ilbc", "G7221", "telephone-event", "TELEPHONE-EVENT", "pcmu", "\u212Aopus", strings.Repeat("A", 70) + "opus"}, equivNames...)
	for _, name := range names {
		for _, raw := range equivFMTP {
			if got, want := canonicalFMTP(name, raw), canonicalFMTPRef(name, raw); got != want {
				t.Errorf("canonicalFMTP(%q, %q) = %q, want %q", name, raw, got, want)
			}
		}
	}
}

func TestFmtpIntMatchesReference(t *testing.T) {
	got, want := fmtpInt(3, 510000), fmtpIntRef(3, 510000)
	vals := []string{"", "0", "00", "3", "03", "003", "10", "010", "120", "0120", "510000", "510001", "0510000",
		"9999999999", "99999999999", "+5", "-5", "5_0", "1e3", " 5", "5 ", "\u0665", "18446744073709551615"}
	for i := 0; i < 2000; i++ {
		vals = append(vals, strconv.Itoa(i), "0"+strconv.Itoa(i))
	}
	for _, v := range vals {
		g, gok := got(v)
		w, wok := want(v)
		if g != w || gok != wok {
			t.Errorf("fmtpInt(%q) = %q, %v; want %q, %v", v, g, gok, w, wok)
		}
	}
}

func randBuild(r *rand.Rand) Build {
	addrs := []netip.Addr{
		netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:1234:5678:9abc:def0:1234:5678"),
		netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("::1"),
		netip.MustParseAddr("0.0.0.0"), {},
	}
	ports := []int{-1, 0, 1, 9, 20000, 65535, 65536}
	ids := []uint64{0, 1, 3921034, 4611731400430051336, 1<<64 - 1}
	dirs := []Direction{"", SendRecv, SendOnly, RecvOnly, Inactive, "weird"}
	setups := []string{"", "passive", "active", "actpass"}
	b := Build{
		Address:        addrs[r.IntN(len(addrs))],
		Port:           ports[r.IntN(len(ports))],
		Codecs:         randCodecs(r, 6),
		Direction:      dirs[r.IntN(len(dirs))],
		SessionID:      ids[r.IntN(len(ids))],
		SessionVersion: ids[r.IntN(len(ids))],
		RTCPMux:        r.IntN(2) == 0,
	}
	if r.IntN(10) == 0 {
		b.Port = 20000 // keep most builds valid
	}
	if r.IntN(3) == 0 {
		b.DTLS = true
		b.ICEUfrag = []string{"", "abcd", "4ZcD"}[r.IntN(3)]
		b.ICEPwd = []string{"", "0123456789abcdef01234567"}[r.IntN(2)]
		b.Setup = setups[r.IntN(len(setups))]
		switch r.IntN(3) {
		case 0:
		case 1:
			b.Fingerprint = &Fingerprint{Hash: "sha-256", Value: benchFP}
		case 2:
			b.Fingerprint = &Fingerprint{}
		}
	}
	if r.IntN(3) == 0 {
		suites := []CryptoSuite{SuiteAESCM128HMACSHA180, SuiteAESCM128HMACSHA132, SuiteAEADAES128GCM, "BOGUS"}
		n := r.IntN(MaxCrypto + 2)
		for i := 0; i < n; i++ {
			s := suites[r.IntN(len(suites))]
			kl, sl, _ := s.Lengths()
			if r.IntN(20) == 0 {
				kl++
			}
			key := make([]byte, kl)
			salt := make([]byte, sl)
			for j := range key {
				key[j] = byte(r.IntN(256))
			}
			for j := range salt {
				salt[j] = byte(r.IntN(256))
			}
			tag := []int{0, 1, 2, 9, 999999999, 1000000000}[r.IntN(6)]
			if r.IntN(2) == 0 {
				tag = i + 1
			}
			b.Crypto = append(b.Crypto, Crypto{Tag: tag, Suite: s, Key: key, Salt: salt})
		}
	}
	return b
}

func randOffer(r *rand.Rand) *Session {
	switch r.IntN(4) {
	case 0:
		return nil
	case 1:
		return &Session{MediaCount: r.IntN(5)}
	}
	protos := [][]string{
		nil, {}, {"RTP", "AVP"}, {"RTP", "SAVPF"}, {"UDP", "TLS", "RTP", "SAVPF"}, {"UDP", "DTLS", "SCTP"},
		{"TCP", "DTLS", "SCTP"}, {"DTLS", "SCTP"}, {"udptl"}, {"TCP", "MSRP"}, {"TCP"}, {"UDP"}, {"UDP", "BFCP"}, {"weird", "x"},
	}
	media := []string{"audio", "video", "application", "image", "message", ""}
	n := r.IntN(6)
	s := &Session{MediaCount: n, AudioIndex: r.IntN(n+2) - 1}
	for i := 0; i < n; i++ {
		s.Sections = append(s.Sections, Section{Media: media[r.IntN(len(media))], Proto: protos[r.IntN(len(protos))]})
	}
	return s
}

// checkBuildMatchesReference compares Marshal and MarshalDeclining with
// the pion-based reference, output and error.
func checkBuildMatchesReference(t *testing.T, b Build, offer *Session) {
	t.Helper()
	got, gerr := b.MarshalDeclining(offer)
	want, werr := b.marshalDecliningPion(offer)
	if errText(gerr) != errText(werr) || !bytes.Equal(got, want) {
		t.Fatalf("MarshalDeclining(%#v) of %#v:\n got %q, %v\nwant %q, %v", offer, b, got, gerr, want, werr)
	}
	got, gerr = b.Marshal()
	want, werr = b.marshalPion(nil)
	if errText(gerr) != errText(werr) || !bytes.Equal(got, want) {
		t.Fatalf("Marshal of %#v:\n got %q, %v\nwant %q, %v", b, got, gerr, want, werr)
	}
}

func TestBuildMatchesPionReference(t *testing.T) {
	r := rand.New(rand.NewPCG(173, 2))
	valid := 0
	const n = 30000
	for i := 0; i < n; i++ {
		b, offer := randBuild(r), randOffer(r)
		checkBuildMatchesReference(t, b, offer)
		if _, err := b.Marshal(); err == nil {
			valid++
		}
	}
	if valid < n/10 {
		t.Fatalf("only %d of the random builds were valid; the comparison is too thin", valid)
	}
	// The benchmark builds and bodies built from the parsed fixtures.
	for _, b := range benchBuildsT(t) {
		checkBuildMatchesReference(t, b, nil)
	}
	for _, body := range []string{phoneOffer, browserOffer, sdesOffer, benchOffers[0].body, benchOffers[1].body, benchOffers[2].body} {
		sess, err := ParseWithOptions([]byte(body), ParseOptions{AllowLoopback: true})
		if err != nil {
			t.Fatal(err)
		}
		b := Build{Address: netip.MustParseAddr("203.0.113.9"), Port: 30000, Codecs: sess.Audio.Codecs, SessionID: 7, SessionVersion: 8, Crypto: sess.Audio.Crypto}
		checkBuildMatchesReference(t, b, sess)
	}
}

func benchBuildsT(t *testing.T) map[string]Build {
	addr := netip.MustParseAddr("198.51.100.7")
	pcmu := Codec{PayloadType: 0, Name: "PCMU", ClockRate: 8000}
	te := Codec{PayloadType: 101, Name: "telephone-event", ClockRate: 8000, FMTP: "0-16"}
	opus := Codec{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2, FMTP: "minptime=10;useinbandfec=1"}
	crypto, err := OfferCrypto()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Build{
		"plain": {Address: addr, Port: 20000, Codecs: []Codec{pcmu, te}, SessionID: 1, SessionVersion: 1},
		"sdes":  {Address: addr, Port: 20000, Codecs: []Codec{pcmu, te}, SessionID: 1, SessionVersion: 1, Crypto: crypto},
		"webrtc": {
			Address: addr, Port: 20000, Codecs: []Codec{opus, pcmu, te}, Direction: SendRecv, SessionID: 1, SessionVersion: 1,
			DTLS: true, RTCPMux: true, ICEUfrag: "abcd", ICEPwd: "0123456789abcdef01234567",
			Fingerprint: &Fingerprint{Hash: "sha-256", Value: benchFP}, Setup: "passive",
		},
	}
}

// TestCryptoValueMatchesReference pins Value (and so Build's a=crypto
// lines) to the rendering it had before issue #173.
func TestCryptoValueMatchesReference(t *testing.T) {
	r := rand.New(rand.NewPCG(173, 3))
	for i := 0; i < 2000; i++ {
		c := Crypto{Tag: r.IntN(1 << 30), Suite: SupportedSuites[r.IntN(len(SupportedSuites))]}
		c.Key = make([]byte, r.IntN(40))
		c.Salt = make([]byte, r.IntN(40))
		for j := range c.Key {
			c.Key[j] = byte(r.IntN(256))
		}
		for j := range c.Salt {
			c.Salt[j] = byte(r.IntN(256))
		}
		mat := append(append([]byte(nil), c.Key...), c.Salt...)
		want := strconv.Itoa(c.Tag) + " " + string(c.Suite) + " inline:" + base64.StdEncoding.EncodeToString(mat)
		if got := c.Value(); got != want {
			t.Fatalf("Value() = %q, want %q", got, want)
		}
	}
}
