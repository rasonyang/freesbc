// Package sdp is FreeSBC's SDP subsystem, shared by both signaling planes:
// a typed, bounded parse of the parts of an offer/answer an SBC acts on
// (audio codecs, connection address, direction, ICE and DTLS attributes),
// codec intersection without transcoding, and construction of the bodies
// the proxy plane emits — a plain RTP/AVP body toward FreeSWITCH and an
// RTP/AVP or WebRTC (UDP/TLS/RTP/SAVPF) body toward the public client.
//
// It holds no policy. WHICH codecs a deployment relays is the decision of
// the plane that relays them and lives there; this package only parses,
// intersects, renders and builds.
//
// It is built on github.com/pion/sdp/v3; there is no string manipulation
// of SDP anywhere in the package. Every input is treated as untrusted:
// Parse enforces size and cardinality limits before doing any work, so a
// malicious offer can neither exhaust memory nor make the proxy build an
// unbounded answer.
//
// Scope is audio only and transcoding-free (spec §5): the proxy relays RTP
// payloads byte-for-byte, so payload-type numbers must survive end to end.
// What makes that work is offer/answer's own recommendation: an answerer
// SHOULD use the offerer's payload-type numbers (RFC 3264 §6.1). The proxy
// therefore forwards the public offer's codec list — numbers included —
// into the offer it makes upstream, and forwards the upstream answer's list
// back out unchanged. An answerer that uses its SHOULD-level freedom to
// renumber is refused (ErrRenumbered, a 488 on the edge) rather than
// bridged, because bridging it would mean rewriting every packet's PT.
package sdp

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	// pion's package is also called sdp; alias it so this package can
	// keep the name that reads best at its own call sites.
	pionsdp "github.com/pion/sdp/v3"
)

// Input limits (spec §16). They bound both parse work and the size of
// anything the proxy derives from a parsed offer.
const (
	// MaxSize is the largest SDP body Parse accepts. Real audio offers are
	// well under 4 KiB even with a full candidate list; 16 KiB leaves room
	// for unusual-but-legitimate bodies without letting a body dominate a
	// SIP message's memory cost.
	MaxSize = 16 << 10
	// MaxMediaDescriptions bounds m= sections.
	MaxMediaDescriptions = 16
	// MaxAttributes bounds a= lines at session level and per media section.
	MaxAttributes = 256
	// MaxCodecs bounds the payload-type list of one audio section. The
	// static space is 0-95 and the dynamic 96-127, so 128 can never reject
	// a well-formed offer.
	MaxCodecs = 128
)

var (
	// ErrTooLarge and friends are returned by Parse for input that breaks
	// a limit. They are distinguishable so the caller can log the class of
	// rejection without echoing attacker-controlled bytes.
	ErrTooLarge  = errors.New("sdp: body exceeds size limit")
	ErrNoAudio   = errors.New("sdp: no audio media section")
	ErrNoAddress = errors.New("sdp: no usable connection address")
	// ErrAudioDeclined is returned by Parse when the body has audio
	// sections but every one is declined (port 0): a legitimate RFC 3264
	// §6 rejection of the stream, as opposed to a body with no audio at
	// all. It wraps ErrNoAudio, so errors.Is(err, ErrNoAudio) matches both.
	ErrAudioDeclined = fmt.Errorf("%w: audio section declined (port 0)", ErrNoAudio)
	// ErrNoCommonCodec is returned by Negotiate when two codec lists share
	// nothing usable — the call must be rejected (488), never transcoded.
	ErrNoCommonCodec = errors.New("sdp: no common codec")
	// ErrRenumbered is returned by Negotiate when the answerer moved a
	// codec to a different payload-type number. Honouring that would need
	// every RTP packet's PT byte rewritten, which is transcoding-adjacent
	// work this proxy does not do — the call is rejected instead.
	ErrRenumbered = errors.New("sdp: answer renumbered a payload type")
)

// Direction is an RFC 4566/3264 media direction attribute.
type Direction string

const (
	SendRecv Direction = "sendrecv"
	SendOnly Direction = "sendonly"
	RecvOnly Direction = "recvonly"
	Inactive Direction = "inactive"
)

// Codec is one payload type of an audio section, as offered or answered.
//
// FMTP is never the other leg's text. Parse keeps only the parameters on a
// per-codec allowlist (fmtp.go), validated against a type and re-rendered
// canonically, and Build applies the same filter again before writing an
// a=fmtp line. What the two endpoints agree on (opus stereo, useinbandfec,
// telephone-event event ranges) still reaches the far side; free text,
// addresses and line breaks do not.
type Codec struct {
	PayloadType uint8
	Name        string // as written, e.g. "opus", "PCMU", "telephone-event"
	ClockRate   uint32
	Channels    int    // 0 when the rtpmap omitted it
	FMTP        string // canonical allowlisted fmtp parameters, without the payload type
}

// key is the transcoding-free identity of a codec: two codecs are the same
// stream if and only if their name (case-insensitively), clock rate and
// channel count agree. The payload NUMBER is deliberately not part of it —
// matching is what lets the proxy detect that both sides mean "opus", and
// the offerer's number is then what both sides use.
func (c Codec) key() string {
	ch := c.Channels
	if ch == 0 {
		ch = 1
	}
	return fmt.Sprintf("%s/%d/%d", strings.ToLower(c.Name), c.ClockRate, ch)
}

// IsTelephoneEvent reports whether this is an RFC 4733 DTMF payload. The
// proxy must keep it in every negotiated list it builds so DTMF survives
// the relay (spec §13).
func (c Codec) IsTelephoneEvent() bool {
	return strings.EqualFold(c.Name, "telephone-event")
}

// String renders the codec the way an rtpmap does, for logs.
func (c Codec) String() string {
	if c.Channels > 1 {
		return fmt.Sprintf("%d %s/%d/%d", c.PayloadType, c.Name, c.ClockRate, c.Channels)
	}
	return fmt.Sprintf("%d %s/%d", c.PayloadType, c.Name, c.ClockRate)
}

// Fingerprint is a DTLS certificate fingerprint from a=fingerprint.
type Fingerprint struct {
	Hash  string // "sha-256", lower-cased
	Value string // colon-separated uppercase hex, as it appears on the wire
}

func (f Fingerprint) String() string { return f.Hash + " " + f.Value }

// Audio is the parsed first audio media section plus the session-level
// context that governs it.
type Audio struct {
	Port  int
	Proto []string // media transport tokens, e.g. ["RTP","AVP"]

	// Address is the connection address media should be sent to: the
	// media-level c= when present, else the session-level one. It is the
	// zero Addr when Hold is set. Parse refuses any other address that
	// cannot be a unicast RTP peer (see ParseOptions).
	Address netip.Addr
	// Hold reports a c= of 0.0.0.0 or :: — RFC 3264 §8.4: send neither
	// RTP nor RTCP to this side. Such a body is valid and must be
	// accepted; it simply names no destination.
	Hold bool
	// Codecs is the section's payload-type list in offer order. Order is
	// preference order and is preserved through every rewrite.
	Codecs    []Codec
	Direction Direction

	// RTCPPort is an explicit a=rtcp port, or 0 when absent.
	RTCPPort int
	// RTCPMux reports a=rtcp-mux (RFC 5761). An answer may carry
	// a=rtcp-mux only when its offer did (RFC 5761 §5.1.1).
	RTCPMux bool

	// ICE/DTLS attributes. Zero values mean "not a WebRTC offer".
	ICEUfrag    string
	ICEPwd      string
	Fingerprint *Fingerprint
	Setup       string // actpass | active | passive | holdconn
}

// WebRTC reports whether the section is a DTLS-SRTP (browser) offer: a
// UDP/TLS transport with both a fingerprint and ICE credentials. All three
// are required — a fingerprint alone (or ICE alone) is a malformed or
// hostile body, not something to build a DTLS session from.
func (a *Audio) WebRTC() bool {
	dtls := false
	for _, p := range a.Proto {
		if p == "TLS" {
			dtls = true
		}
	}
	return dtls && a.Fingerprint != nil && a.ICEUfrag != "" && a.ICEPwd != ""
}

// Session is a parsed SDP body: the audio section the proxy relays, plus
// what it needs to build a matching body for the other leg.
type Session struct {
	// Audio is the first live audio m= section. Parse fails when there is
	// none.
	Audio *Audio
	// MediaCount is how many m= sections the body had, including the ones
	// the proxy declines.
	MediaCount int
	// AudioIndex is the position of Audio among the body's m= sections.
	// An answer must put its live audio section at the same index
	// (RFC 3264 §6).
	AudioIndex int
	// Sections is the media type and transport of every m= section, in
	// order, so an answer can decline each one with a matching m= line.
	// Both are normalised (see Section); nothing else is kept.
	Sections []Section
}

// Section is what an answer needs to decline one offered m= section: its
// media type and transport protocol. Both are checked against a fixed
// grammar before they are kept, because they are echoed into the body
// built for the other leg.
type Section struct {
	Media string   // "audio", "video", ...: letters only, lower-cased
	Proto []string // e.g. ["RTP","AVP"]; one of knownProtos
}

// ErrNotUnicast reports a connection address that can never be a unicast
// RTP peer (multicast, broadcast, link-local), or a loopback address the
// caller did not allow. It wraps ErrNoAddress.
var ErrNotUnicast = fmt.Errorf("%w: not a unicast media address", ErrNoAddress)

// ParseOptions is the caller's policy for what Parse accepts.
type ParseOptions struct {
	// AllowLoopback accepts a loopback c=. A loopback media address is
	// legitimate only when the SBC's own media plane is on loopback (a
	// single-host lab, the test suites); from a real client it points the
	// SBC's media socket at a service on its own host. The media plane
	// applies its own per-pool policy again before sending anything.
	AllowLoopback bool
}

// Parse decodes and validates one SDP body, refusing a loopback c=. It is
// ParseWithOptions with the zero ParseOptions.
func Parse(body []byte) (*Session, error) {
	return ParseWithOptions(body, ParseOptions{})
}

// ParseWithOptions decodes and validates one SDP body under opts.
func ParseWithOptions(body []byte, opts ParseOptions) (*Session, error) {
	if len(body) == 0 {
		return nil, errors.New("sdp: empty body")
	}
	if len(body) > MaxSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooLarge, len(body), MaxSize)
	}
	var sd pionsdp.SessionDescription
	if err := sd.Unmarshal(body); err != nil {
		return nil, fmt.Errorf("sdp: parse: %w", err)
	}
	if len(sd.MediaDescriptions) > MaxMediaDescriptions {
		return nil, fmt.Errorf("%w: %d media sections", ErrTooLarge, len(sd.MediaDescriptions))
	}
	if len(sd.Attributes) > MaxAttributes {
		return nil, fmt.Errorf("%w: %d session attributes", ErrTooLarge, len(sd.Attributes))
	}

	var md *pionsdp.MediaDescription
	audioIndex, declinedAudio := 0, false
	sections := make([]Section, 0, len(sd.MediaDescriptions))
	for i, m := range sd.MediaDescriptions {
		if len(m.Attributes) > MaxAttributes {
			return nil, fmt.Errorf("%w: %d media attributes", ErrTooLarge, len(m.Attributes))
		}
		sections = append(sections, section(m))
		// The FIRST audio section is the one relayed; a declined (port 0)
		// section is skipped so a body that offers a dead audio stream
		// followed by a live one still works.
		if md == nil && m.MediaName.Media == "audio" {
			if m.MediaName.Port.Value == 0 {
				declinedAudio = true
			} else {
				md, audioIndex = m, i
			}
		}
	}
	if md == nil {
		if declinedAudio {
			return nil, ErrAudioDeclined
		}
		return nil, ErrNoAudio
	}
	if len(md.MediaName.Formats) > MaxCodecs {
		return nil, fmt.Errorf("%w: %d payload types", ErrTooLarge, len(md.MediaName.Formats))
	}

	a := &Audio{
		Port:      md.MediaName.Port.Value,
		Proto:     append([]string(nil), md.MediaName.Protos...),
		Direction: SendRecv,
	}
	if err := parseConnection(&sd, md, a, opts); err != nil {
		return nil, err
	}
	parseAttributes(&sd, md, a)
	var err error
	if a.Codecs, err = parseCodecs(md); err != nil {
		return nil, err
	}
	if len(a.Codecs) == 0 {
		return nil, errors.New("sdp: audio section has no payload types")
	}

	return &Session{
		Audio:      a,
		MediaCount: len(sd.MediaDescriptions),
		AudioIndex: audioIndex,
		Sections:   sections,
	}, nil
}

// knownProtos is every transport an answer may echo when it declines a
// section. An unknown one is answered as RTP/AVP: the proto of a rejected
// stream is moot, and echoing an unvetted token would carry the other
// leg's text across.
var knownProtos = map[string]bool{
	"RTP/AVP": true, "RTP/AVPF": true, "RTP/SAVP": true, "RTP/SAVPF": true,
	"UDP/TLS/RTP/SAVP": true, "UDP/TLS/RTP/SAVPF": true,
	"TCP/TLS/RTP/SAVP": true, "TCP/TLS/RTP/SAVPF": true,
	"TCP/DTLS/RTP/SAVP": true, "TCP/DTLS/RTP/SAVPF": true,
	"UDP/DTLS/SCTP": true, "TCP/DTLS/SCTP": true, "DTLS/SCTP": true,
	"udptl": true, "TCP/MSRP": true, "TCP/TLS/MSRP": true,
	"UDP/BFCP": true, "TCP/BFCP": true, "TCP/TLS/BFCP": true,
	"TCP": true, "UDP": true,
}

// section normalises one m= line into what a declining answer echoes.
func section(m *pionsdp.MediaDescription) Section {
	media := strings.ToLower(m.MediaName.Media)
	if media == "" || len(media) > 32 || strings.IndexFunc(media, func(r rune) bool { return r < 'a' || r > 'z' }) >= 0 {
		media = "audio"
	}
	proto := []string{"RTP", "AVP"}
	if knownProtos[strings.Join(m.MediaName.Protos, "/")] {
		proto = append([]string(nil), m.MediaName.Protos...)
	}
	return Section{Media: media, Proto: proto}
}

func parseConnection(sd *pionsdp.SessionDescription, md *pionsdp.MediaDescription, a *Audio, opts ParseOptions) error {
	conn := md.ConnectionInformation
	if conn == nil {
		conn = sd.ConnectionInformation
	}
	if conn == nil || conn.Address == nil {
		return ErrNoAddress
	}
	// A hostname (rather than a literal) is not resolved here: the proxy
	// must not perform DNS on behalf of an untrusted body, and every
	// endpoint it talks to signals a literal address in practice.
	ip, err := netip.ParseAddr(strings.TrimSpace(conn.Address.Address))
	if err != nil {
		return fmt.Errorf("%w: %q", ErrNoAddress, conn.Address.Address)
	}
	ip = ip.Unmap()
	switch {
	case ip.IsUnspecified():
		a.Hold = true // RFC 3264 §8.4: valid, but no destination
	case ip.IsMulticast(), ip.IsLinkLocalUnicast(),
		ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%w: %s", ErrNotUnicast, ip)
	case ip.IsLoopback() && !opts.AllowLoopback:
		return fmt.Errorf("%w: loopback %s", ErrNotUnicast, ip)
	default:
		a.Address = ip
	}
	return nil
}

// parseAttributes reads the session-level attributes first and then the
// media-level ones, so a media-level value overrides the session-level one
// per RFC 4566 §5.13.
func parseAttributes(sd *pionsdp.SessionDescription, md *pionsdp.MediaDescription, a *Audio) {
	apply := func(attrs []pionsdp.Attribute) {
		for _, at := range attrs {
			v := strings.TrimSpace(at.Value)
			switch at.Key {
			case "sendrecv", "sendonly", "recvonly", "inactive":
				a.Direction = Direction(at.Key)
			case "ice-ufrag":
				a.ICEUfrag = sanitizeICEToken(v, minICEUfrag)
			case "ice-pwd":
				a.ICEPwd = sanitizeICEToken(v, minICEPwd)
			case "rtcp-mux":
				a.RTCPMux = true
			case "setup":
				switch v {
				case "active", "passive", "actpass", "holdconn":
					a.Setup = v
				}
			case "fingerprint":
				if fp, ok := parseFingerprint(v); ok {
					a.Fingerprint = &fp
				}
			case "rtcp":
				// "a=rtcp:<port> [IN IP4 <addr>]" — only the port matters
				// to the proxy; the optional address is topology it must
				// not carry across. A bare "a=rtcp" (or "a=rtcp:") carries
				// no port at all and must not be indexed into.
				if f := strings.Fields(v); len(f) > 0 {
					if p, err := strconv.Atoi(f[0]); err == nil && p > 0 && p < 65536 {
						a.RTCPPort = p
					}
				}
			}
		}
	}
	apply(sd.Attributes)
	apply(md.Attributes)
}

// parseCodecs builds the section's codec list from its format list, its
// a=rtpmap lines and its a=fmtp lines. Formats with no rtpmap fall back to
// the RFC 3551 static table, which is how a bare "m=audio ... 0 8" offer
// (still common from SIP hardware) is understood.
func parseCodecs(md *pionsdp.MediaDescription) ([]Codec, error) {
	rtpmap := map[uint8]string{}
	fmtp := map[uint8]string{}
	for _, at := range md.Attributes {
		switch at.Key {
		case "rtpmap":
			if pt, rest, ok := splitPayload(at.Value); ok {
				rtpmap[pt] = rest
			}
		case "fmtp":
			if pt, rest, ok := splitPayload(at.Value); ok {
				fmtp[pt] = rest
			}
		}
	}
	var out []Codec
	seen := map[uint8]bool{}
	for _, f := range md.MediaName.Formats {
		f = strings.TrimSpace(f)
		if f == "" || strings.IndexFunc(f, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return nil, fmt.Errorf("sdp: bad payload type %q", f)
		}
		n, err := strconv.ParseUint(f, 10, 8)
		if err != nil || n > 127 || seen[uint8(n)] {
			// A number above 127 (including one too large for a byte) is
			// outside the RTP payload-type space; a duplicate is
			// malformed. Skip rather than fail: the rest of the list may
			// still be a perfectly usable offer. Only a format that is not
			// a number at all fails the body.
			continue
		}
		pt := uint8(n)
		seen[pt] = true
		c := Codec{PayloadType: pt}
		if m, ok := rtpmap[pt]; ok {
			name, rate, ch, ok := parseRTPMap(m)
			if !ok {
				continue
			}
			c.Name, c.ClockRate, c.Channels = name, rate, ch
		} else if st, ok := staticPayload(pt); ok {
			c.Name, c.ClockRate, c.Channels = st.Name, st.ClockRate, st.Channels
		} else {
			continue // dynamic payload type with no rtpmap: unusable
		}
		c.FMTP = canonicalFMTP(c.Name, fmtp[pt])
		out = append(out, c)
	}
	return out, nil
}

// splitPayload splits "<pt> <rest>" as used by rtpmap and fmtp.
func splitPayload(v string) (uint8, string, bool) {
	pt, rest, ok := strings.Cut(strings.TrimSpace(v), " ")
	if !ok {
		return 0, "", false
	}
	n, err := strconv.ParseUint(pt, 10, 8)
	if err != nil || n > 127 {
		return 0, "", false
	}
	return uint8(n), strings.TrimSpace(rest), true
}

// parseRTPMap parses "<name>/<clock>[/<channels>]".
func parseRTPMap(v string) (name string, rate uint32, channels int, ok bool) {
	parts := strings.Split(v, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return "", 0, 0, false
	}
	name = strings.TrimSpace(parts[0])
	if !validEncodingName(name) {
		return "", 0, 0, false
	}
	r, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
	if err != nil || r == 0 {
		return "", 0, 0, false
	}
	channels = 1
	if len(parts) == 3 {
		ch, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err != nil || ch < 1 || ch > 8 {
			return "", 0, 0, false
		}
		channels = ch
	}
	return name, uint32(r), channels, true
}

// staticEntry is one RFC 3551 static payload type.
type staticEntry struct {
	Name      string
	ClockRate uint32
	Channels  int
}

// staticPayload returns the RFC 3551 definition of a static audio payload
// type. Only the ones this proxy supports are listed: an unknown static
// type has no rtpmap to describe it and cannot be negotiated safely.
func staticPayload(pt uint8) (staticEntry, bool) {
	switch pt {
	case 0:
		return staticEntry{"PCMU", 8000, 1}, true
	case 8:
		return staticEntry{"PCMA", 8000, 1}, true
	}
	return staticEntry{}, false
}

// validEncodingName reports whether an rtpmap encoding name is 1-64 bytes
// of letters, digits, '-', '_' and '.'. Every registered audio encoding
// name fits ("PCMU", "telephone-event", "AMR-WB", "G7221"); the name is
// re-rendered into the body built for the other leg and into log lines,
// so anything else — spaces, CR/LF, quotes — makes the codec unusable.
func validEncodingName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !alnum && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// ICE credential lengths, RFC 5245 §15.4: ice-ufrag is 4-256 ice-chars,
// ice-pwd 22-256.
const (
	minICEUfrag = 4
	minICEPwd   = 22
	maxICEToken = 256
)

// sanitizeICEToken keeps only the RFC 5245 ice-char set. An ICE ufrag or
// password is copied into the SDP the proxy generates for the other leg
// (and compared against STUN attributes), so anything outside the allowed
// alphabet — CR/LF above all — is dropped rather than echoed, as is a
// token shorter than minLen or longer than maxICEToken.
func sanitizeICEToken(v string, minLen int) string {
	if len(v) < minLen || len(v) > maxICEToken {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !alnum && c != '+' && c != '/' && c != '-' && c != '_' {
			return ""
		}
	}
	return v
}

// parseFingerprint parses "<hash-func> <hex:hex:...>" and validates both
// halves. Only SHA-256 and stronger are accepted: SHA-1 fingerprints are
// still seen from old stacks but are not a defensible binding for a media
// path this proxy terminates.
func parseFingerprint(v string) (Fingerprint, bool) {
	hash, val, ok := strings.Cut(strings.TrimSpace(v), " ")
	if !ok {
		return Fingerprint{}, false
	}
	hash = strings.ToLower(strings.TrimSpace(hash))
	var want int
	switch hash {
	case "sha-256":
		want = 32
	case "sha-384":
		want = 48
	case "sha-512":
		want = 64
	default:
		return Fingerprint{}, false
	}
	val = strings.TrimSpace(val)
	parts := strings.Split(val, ":")
	if len(parts) != want {
		return Fingerprint{}, false
	}
	for _, p := range parts {
		if len(p) != 2 || !isHexByte(p) {
			return Fingerprint{}, false
		}
	}
	return Fingerprint{Hash: hash, Value: strings.ToUpper(val)}, true
}

// isHexByte reports whether s is all hex digits (RFC 8122 §5 UHEX, either
// case).
func isHexByte(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
