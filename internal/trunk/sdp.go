package trunk

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/freesbc/freesbc/internal/media"
	fsdp "github.com/freesbc/freesbc/internal/sip/sdp"
)

// Trunk SDP: every body the bridge sends is BUILT, never edited.
//
// The trunk reads a peer's body with a small, tolerant line parser
// (parseSDP) and then writes the other leg's body from scratch
// (sdpOrigin.build) out of an allow-list: the SBC's own o=, s= and c=, the
// relayed audio section at the SBC's own port with only its codec lines
// (rtpmap, fmtp with allow-listed parameters, ptime, maxptime) and
// direction, and every other section declined at port 0 with no attributes
// (RFC 3264 §6). Nothing else from the peer's body — ICE candidates,
// fingerprints, SSRCs, session attributes, the peer's o= identity or any
// address — can reach the other leg, because nothing copies it.
//
// The parser is deliberately not pion/sdp or the edge plane's bounded
// sdp.Parse: pion rejects any media type outside audio|video|text|
// application|message (so an offer with a T.38 m=image section could not be
// placed at all), and the trunk is a relay between carriers that must not
// refuse a body on size or codec policy the peers agreed between
// themselves. What the parser accepts is bounded by what the builder emits.

// sdpAttr is one a= line: key and, when the line had a ':', its value.
type sdpAttr struct {
	key, value string
}

// sdpSection is one m= section as the peer wrote it.
type sdpSection struct {
	media string   // "audio", "video", "image", ...
	port  int      // 0 = declined by the peer
	proto string   // e.g. "RTP/AVP", "udptl"
	fmts  []string // the m= line's format tokens
	conn  string   // media-level c= address token, "" if none
	attrs []sdpAttr
}

// sdpBody is a parsed peer body: the session-level c= and attributes, and
// the m= sections in order.
type sdpBody struct {
	conn     string
	attrs    []sdpAttr
	sections []*sdpSection
}

var (
	errSDPNoAudio   = errors.New("sdp has no audio media")
	errSDPMalformed = errors.New("malformed sdp")
)

// parseSDP reads the lines of an SDP body that the trunk cares about. It
// accepts CRLF or bare LF, ignores line types it does not use, and fails
// only on a body that is not SDP at all: no v= line first, a line that is
// not "<letter>=<value>", or an unreadable m= or c= line.
func parseSDP(body []byte) (*sdpBody, error) {
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	b := &sdpBody{}
	var cur *sdpSection
	sawVersion := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		if len(line) < 2 || line[1] != '=' {
			return nil, fmt.Errorf("%w: line %q", errSDPMalformed, line)
		}
		typ, val := line[0], line[2:]
		if !sawVersion {
			if typ != 'v' {
				return nil, fmt.Errorf("%w: body does not start with v=", errSDPMalformed)
			}
			sawVersion = true
			continue
		}
		switch typ {
		case 'm':
			sec, err := parseMediaLine(val)
			if err != nil {
				return nil, err
			}
			b.sections = append(b.sections, sec)
			cur = sec
		case 'c':
			addr, err := parseConnectionLine(val)
			if err != nil {
				return nil, err
			}
			if cur != nil {
				cur.conn = addr
			} else {
				b.conn = addr
			}
		case 'a':
			a := sdpAttr{key: val}
			if i := strings.IndexByte(val, ':'); i >= 0 {
				a = sdpAttr{key: val[:i], value: val[i+1:]}
			}
			if cur != nil {
				cur.attrs = append(cur.attrs, a)
			} else {
				b.attrs = append(b.attrs, a)
			}
		}
	}
	if !sawVersion {
		return nil, fmt.Errorf("%w: empty body", errSDPMalformed)
	}
	return b, nil
}

// parseMediaLine reads "<media> <port>[/<n>] <proto> <fmt> ...".
func parseMediaLine(val string) (*sdpSection, error) {
	f := strings.Fields(val)
	if len(f) < 3 {
		return nil, fmt.Errorf("%w: m=%s", errSDPMalformed, val)
	}
	portTok := f[1]
	if i := strings.IndexByte(portTok, '/'); i >= 0 {
		portTok = portTok[:i]
	}
	port, err := strconv.Atoi(portTok)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("%w: m= port %q", errSDPMalformed, f[1])
	}
	return &sdpSection{media: f[0], port: port, proto: f[2], fmts: f[3:]}, nil
}

// parseConnectionLine reads "IN <IP4|IP6> <address>[/ttl[/n]]" and returns
// the address token, which may be an FQDN (RFC 4566 §5.7).
func parseConnectionLine(val string) (string, error) {
	f := strings.Fields(val)
	if len(f) != 3 || f[0] != "IN" || (f[1] != "IP4" && f[1] != "IP6") {
		return "", fmt.Errorf("%w: c=%s", errSDPMalformed, val)
	}
	addr := f[2]
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	if addr == "" {
		return "", fmt.Errorf("%w: c=%s", errSDPMalformed, val)
	}
	return addr, nil
}

// audio is the one section the bridge relays: the first m=audio whose port
// is non-zero. A port-0 section is declined by the peer (RFC 3264 §6) and
// carries no media, so skipping it keeps the latch address (remoteMediaIP)
// and the section the builder relays pointing at the same m= line.
func (b *sdpBody) audio() *sdpSection {
	for _, s := range b.sections {
		if s.media == "audio" && s.port != 0 {
			return s
		}
	}
	return nil
}

// parseAudioSDP parses body and returns it with its relayed audio section.
func parseAudioSDP(body []byte) (*sdpBody, *sdpSection, error) {
	b, err := parseSDP(body)
	if err != nil {
		return nil, nil, fmt.Errorf("parse sdp: %w", err)
	}
	a := b.audio()
	if a == nil {
		return nil, nil, errSDPNoAudio
	}
	if len(relayFormats(a)) == 0 {
		return nil, nil, fmt.Errorf("sdp audio section has no RTP payload types")
	}
	return b, a, nil
}

// remoteMediaIP returns the connection address the peer expects media
// from: the relayed audio section's media-level c= if present, otherwise
// the session-level c=. Used to arm the media latch.
//
// c= may carry an FQDN (RFC 4566 §5.7). The trunk does not resolve it on
// the call path; it returns the zero Addr with no error, and the caller
// then latches that side to the first packet (see expectRemote).
func remoteMediaIP(body []byte) (netip.Addr, error) {
	b, a, err := parseAudioSDP(body)
	if err != nil {
		return netip.Addr{}, err
	}
	conn := a.conn
	if conn == "" {
		conn = b.conn
	}
	if conn == "" {
		return netip.Addr{}, fmt.Errorf("sdp has no connection address")
	}
	ip, err := netip.ParseAddr(conn)
	if err != nil {
		return netip.Addr{}, nil // an FQDN: no address to be strict about
	}
	return ip, nil
}

// validAudioSDP reports whether body is an SDP the bridge can relay: it
// parses and carries a live audio m= section with at least one RTP payload
// type. It is the target-independent half of what the builder would
// reject, checked once up front in placeCall so the same offer doesn't fail
// identically on every failover attempt.
func validAudioSDP(body []byte) error {
	_, _, err := parseAudioSDP(body)
	return err
}

// sdpCrypto is what to advertise on the relayed audio section: a suite, the
// SBC's own 30-byte inline key value, and the a=crypto tag to advertise it
// under. A nil *sdpCrypto means plaintext.
//
// tag matters for RFC 4568 §5.1.3 interop: when the SBC is the ANSWERER
// (A-leg answer), it must echo the tag of whichever offered line it
// SELECTED, not always tag 1 — an offerer that listed an unsupported suite
// at tag 1 and a supported one at tag 2 expects the answer's key to be
// associated with tag 2. When the SBC is the OFFERER (B-leg offer), it only
// ever offers one line, so tag is always 1 there.
type sdpCrypto struct {
	suite    media.CryptoSuite
	keyValue []byte
	tag      int
}

// offeredCrypto reports whether the relayed audio section is SRTP (proto
// RTP/SAVP, or RTP/SAVPF — RFC 5124) and returns its parsed, supported
// a=crypto lines (empty if none).
func offeredCrypto(body []byte) (secure bool, lines []cryptoLine) {
	_, a, err := parseAudioSDP(body)
	if err != nil {
		return false, nil
	}
	var values []string
	for _, at := range a.attrs {
		if at.key == "crypto" {
			values = append(values, at.value)
		}
	}
	return isSecureProto(a.proto), parseCryptoAttrs(values)
}

// isSecureProto reports whether an m= proto is an SRTP RTP profile.
func isSecureProto(proto string) bool {
	return proto == "RTP/SAVP" || proto == "RTP/SAVPF"
}

// sdpOrigin is the SBC's own o= identity for one leg (RFC 3264 §8, RFC
// 6337 §3.1): one session-id for the life of the leg, whose version moves
// by exactly one each time the body the SBC sends on that leg changes. It
// is what keeps the caller's o= stable across early media, the final
// answer and failover, whichever carrier the body was derived from. Safe
// for concurrent use.
type sdpOrigin struct {
	mu      sync.Mutex
	id      uint64
	version uint64
	last    string // the previous body without its o= line
}

// newSDPOrigin returns an origin with a random session-id.
func newSDPOrigin() *sdpOrigin {
	var b [8]byte
	_, _ = rand.Read(b[:])
	// Keep it a positive 63-bit value: some stacks parse o= numbers as
	// signed 64-bit.
	id := binary.BigEndian.Uint64(b[:]) >> 1
	return &sdpOrigin{id: id, version: 1}
}

// rewriteSDPCrypto builds a one-shot body for a leg from the other leg's
// body, with a fresh origin; see sdpOrigin.build.
func rewriteSDPCrypto(body []byte, mediaIP netip.Addr, rtpPort int, crypto *sdpCrypto) ([]byte, error) {
	return newSDPOrigin().build(body, mediaIP, rtpPort, crypto)
}

// build writes the body the SBC sends on this origin's leg, derived from the
// other leg's body src: the SBC's own o=/s=/c= at mediaIP, the relayed
// audio section at rtpPort with proto RTP/SAVP plus one a=crypto (ours,
// tagged crypto.tag) when crypto is non-nil or RTP/AVP otherwise, and every
// other section of src declined at port 0, in order. See the file comment
// for what the relayed section may carry.
func (o *sdpOrigin) build(src []byte, mediaIP netip.Addr, rtpPort int, crypto *sdpCrypto) ([]byte, error) {
	b, relay, err := parseAudioSDP(src)
	if err != nil {
		return nil, err
	}
	if !mediaIP.IsValid() || rtpPort <= 0 || rtpPort > 65535 {
		return nil, fmt.Errorf("sdp: bad local media address %v:%d", mediaIP, rtpPort)
	}
	addrType := fsdp.AddrType(mediaIP)

	var w strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&w, format, args...)
		w.WriteString("\r\n")
	}
	line("s=FreeSBC")
	line("c=IN %s %s", addrType, mediaIP)
	line("t=0 0")
	for _, sec := range b.sections {
		if sec != relay {
			writeDeclined(line, sec)
			continue
		}
		proto := "RTP/AVP"
		if crypto != nil {
			proto = "RTP/SAVP"
		}
		fmts := relayFormats(sec)
		line("m=audio %d %s %s", rtpPort, proto, strings.Join(fmts, " "))
		writeCodecAttrs(line, sec, fmts)
		if dir := direction(sec.attrs, b.attrs); dir != "" {
			line("a=%s", dir)
		}
		for _, a := range sec.attrs {
			if a.key == "rtcp" {
				line("a=rtcp:%d", rtpPort+1)
				break
			}
		}
		if crypto != nil {
			line("a=crypto:%s", cryptoAttrValue(crypto.tag, crypto.suite, crypto.keyValue))
		}
	}
	rest := w.String()

	o.mu.Lock()
	if o.last != "" && o.last != rest {
		o.version++
	}
	o.last = rest
	id, version := o.id, o.version
	o.mu.Unlock()

	return []byte(fmt.Sprintf("v=0\r\no=FreeSBC %d %d IN %s %s\r\n", id, version, addrType, mediaIP) + rest), nil
}

// writeDeclined writes a section the bridge does not relay as an RFC 3264
// §6 rejected stream: the same media type, proto and formats, port 0, and
// nothing else — no c=, no attributes, so none of the peer's keys,
// candidates or addresses ride along.
func writeDeclined(line func(string, ...any), sec *sdpSection) {
	fmts := sec.fmts
	if len(fmts) == 0 {
		fmts = []string{"0"}
	}
	var clean []string
	for _, f := range fmts {
		if isToken(f) {
			clean = append(clean, f)
		}
	}
	if len(clean) == 0 {
		clean = []string{"0"}
	}
	media, proto := sec.media, sec.proto
	if !isToken(media) || !isToken(proto) {
		media, proto = "audio", "RTP/AVP"
	}
	line("m=%s 0 %s %s", media, proto, strings.Join(clean, " "))
}

// relayFormats returns the relayed section's RTP payload types: the m=
// format tokens that are decimal 0-127, in order.
func relayFormats(sec *sdpSection) []string {
	var out []string
	for _, f := range sec.fmts {
		if n, err := strconv.Atoi(f); err == nil && n >= 0 && n <= 127 && strconv.Itoa(n) == f {
			out = append(out, f)
		}
	}
	return out
}

// writeCodecAttrs writes the relayed section's rtpmap and fmtp lines for
// the relayed payload types, rebuilt from their parsed parts, plus ptime
// and maxptime.
func writeCodecAttrs(line func(string, ...any), sec *sdpSection, fmts []string) {
	relayed := make(map[string]bool, len(fmts))
	for _, f := range fmts {
		relayed[f] = true
	}
	for _, a := range sec.attrs {
		switch a.key {
		case "rtpmap":
			if pt, enc, ok := splitPT(a.value); ok && relayed[pt] {
				if v, ok := cleanRTPMap(enc); ok {
					line("a=rtpmap:%s %s", pt, v)
				}
			}
		case "fmtp":
			if pt, params, ok := splitPT(a.value); ok && relayed[pt] {
				if v := cleanFMTP(params); v != "" {
					line("a=fmtp:%s %s", pt, v)
				}
			}
		case "ptime", "maxptime":
			if isSmallNumber(a.value, 4) {
				line("a=%s:%s", a.key, a.value)
			}
		}
	}
}

// direction returns the relayed section's direction attribute, falling
// back to the session-level one; "" when neither states one.
func direction(media, session []sdpAttr) string {
	for _, attrs := range [][]sdpAttr{media, session} {
		for _, a := range attrs {
			switch a.key {
			case "sendrecv", "sendonly", "recvonly", "inactive":
				return a.key
			}
		}
	}
	return ""
}

// splitPT splits "<pt> <rest>" and checks pt is a payload-type number.
func splitPT(v string) (pt, rest string, ok bool) {
	pt, rest, found := strings.Cut(strings.TrimSpace(v), " ")
	if !found || !isSmallNumber(pt, 3) {
		return "", "", false
	}
	return pt, strings.TrimSpace(rest), true
}

// cleanRTPMap validates "<encoding>/<clock rate>[/<channels>]" and returns
// it rebuilt.
func cleanRTPMap(v string) (string, bool) {
	parts := strings.Split(v, "/")
	if len(parts) < 2 || len(parts) > 3 || !isToken(parts[0]) || !isSmallNumber(parts[1], 6) {
		return "", false
	}
	if len(parts) == 3 && !isSmallNumber(parts[2], 2) {
		return "", false
	}
	return strings.Join(parts, "/"), true
}

// fmtpParams is the allow-list of named fmtp parameters the bridge relays:
// the ones the common narrowband and wideband voice codecs define (G.729
// annexb, G.723.1, iLBC mode, AMR/AMR-WB (RFC 4867), Opus (RFC 7587), EVS
// (3GPP TS 26.445), G.722.1, Speex, SILK). Anything else — vendor x-
// parameters in particular — is dropped.
var fmtpParams = map[string]bool{
	"annexa": true, "annexb": true, "bitrate": true, "mode": true,
	"octet-align": true, "mode-set": true, "mode-change-period": true,
	"mode-change-capability": true, "mode-change-neighbor": true, "crc": true,
	"robust-sorting": true, "interleaving": true, "max-red": true, "channels": true,
	"maxplaybackrate": true, "sprop-maxcapturerate": true, "maxptime": true,
	"ptime": true, "minptime": true, "maxaveragebitrate": true, "stereo": true,
	"sprop-stereo": true, "cbr": true, "useinbandfec": true, "usedtx": true,
	"evs-mode-switch": true, "hf-only": true, "dtx": true, "dtx-recv": true,
	"br": true, "bw": true, "br-send": true, "br-recv": true, "bw-send": true,
	"bw-recv": true, "cmr": true, "ch-send": true, "ch-recv": true, "ch-aw-recv": true,
	"vbr": true, "cng": true,
}

// cleanFMTP keeps the fmtp parameters the bridge understands: allow-listed
// name=value pairs with plain values, and the bare lists telephone-event
// (RFC 4733: "0-15,32") and RED (RFC 2198: "0/0") use, whose numbers are all
// at most 255 — which is what keeps an address or port from riding along.
func cleanFMTP(params string) string {
	var kept []string
	for _, p := range strings.Split(params, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if name, value, ok := strings.Cut(p, "="); ok {
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if fmtpParams[strings.ToLower(name)] && isParamValue(value) {
				kept = append(kept, name+"="+value)
			}
			continue
		}
		if isNumberList(p) {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ";")
}

// isNumberList reports whether s is a list of numbers 0-255 joined by
// ',', '-' or '/', e.g. "0-15,32" or "0/0".
func isNumberList(s string) bool {
	for _, n := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '-' || r == '/' }) {
		if !isSmallNumber(n, 3) {
			return false
		}
		if v, _ := strconv.Atoi(n); v > 255 {
			return false
		}
	}
	return s != "" && strings.Trim(s, "0123456789,-/") == ""
}

// isParamValue reports whether v is a short plain fmtp value: digits,
// letters and ',', '.', '-', at most 32 characters.
func isParamValue(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == ',' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// isSmallNumber reports whether s is 1 to maxDigits decimal digits.
func isSmallNumber(s string, maxDigits int) bool {
	if s == "" || len(s) > maxDigits {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isToken reports whether s is a non-empty SDP token (RFC 4566 §9 token,
// plus '/' for proto): printable ASCII with no space or separator that
// could start a new field or line.
func isToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune("\"(),:;<=>?@[\\]{}", r) {
			return false
		}
	}
	return true
}
