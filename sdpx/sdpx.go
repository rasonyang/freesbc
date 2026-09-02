// Package sdpx is FreeSBC's SDP subsystem for the edge proxy: a typed,
// bounded parse of the parts of an offer/answer the proxy actually acts on
// (audio codecs, connection address, direction, ICE and DTLS attributes),
// codec intersection without transcoding, and construction of the two
// SDPs the proxy emits — a plain RTP/AVP body toward FreeSWITCH and an
// RTP/AVP or WebRTC (UDP/TLS/RTP/SAVPF) body toward the public client.
//
// It is built on github.com/pion/sdp/v3; there is no string manipulation
// of SDP anywhere in the package. Every input is treated as untrusted:
// Parse enforces size and cardinality limits before doing any work, so a
// malicious offer can neither exhaust memory nor make the proxy build an
// unbounded answer.
//
// Scope is audio only and transcoding-free (spec §5): the proxy relays RTP
// payloads byte-for-byte, so payload-type numbers must survive end to end.
// The rule that makes that work is offer/answer's own: an answerer uses
// the offerer's payload-type numbers. The proxy therefore forwards the
// public offer's codec list — numbers included — into the offer it makes
// upstream, and forwards the upstream answer's list back out unchanged.
package sdpx

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/pion/sdp/v3"
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
	// MaxCandidates bounds a=candidate lines kept per media section.
	MaxCandidates = 64
)

var (
	// ErrTooLarge and friends are returned by Parse for input that breaks
	// a limit. They are distinguishable so the caller can log the class of
	// rejection without echoing attacker-controlled bytes.
	ErrTooLarge  = errors.New("sdpx: body exceeds size limit")
	ErrNoAudio   = errors.New("sdpx: no audio media section")
	ErrNoAddress = errors.New("sdpx: no usable connection address")
	// ErrNoCommonCodec is returned by Intersect when two codec lists share
	// nothing usable — the call must be rejected (488), never transcoded.
	ErrNoCommonCodec = errors.New("sdpx: no common codec")
)

// Direction is an RFC 4566/3264 media direction attribute.
type Direction string

const (
	SendRecv Direction = "sendrecv"
	SendOnly Direction = "sendonly"
	RecvOnly Direction = "recvonly"
	Inactive Direction = "inactive"
)

// Reverse returns the direction the other side of a relay must advertise
// for the same stream: a caller that only sends must face a peer that only
// receives. sendrecv and inactive are their own reverses.
func (d Direction) Reverse() Direction {
	switch d {
	case SendOnly:
		return RecvOnly
	case RecvOnly:
		return SendOnly
	default:
		return d
	}
}

// Codec is one payload type of an audio section, as offered or answered.
// FMTP is carried verbatim: the proxy never rewrites codec parameters
// because it never transcodes, so whatever the two endpoints agree on
// (opus stereo, useinbandfec, telephone-event event ranges) must reach the
// far side exactly as written.
type Codec struct {
	PayloadType uint8
	Name        string // as written, e.g. "opus", "PCMU", "telephone-event"
	ClockRate   uint32
	Channels    int    // 0 when the rtpmap omitted it
	FMTP        string // the a=fmtp value, without the payload type
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
	// media-level c= when present, else the session-level one.
	Address netip.Addr
	// Codecs is the section's payload-type list in offer order. Order is
	// preference order and is preserved through every rewrite.
	Codecs    []Codec
	Direction Direction

	// RTCPPort is an explicit a=rtcp port, or 0 when absent.
	RTCPPort int
	// RTCPMux is set when a=rtcp-mux is present.
	RTCPMux bool

	// ICE/DTLS attributes. Zero values mean "not a WebRTC offer".
	ICEUfrag    string
	ICEPwd      string
	ICELite     bool
	Candidates  []string
	Fingerprint *Fingerprint
	Setup       string // actpass | active | passive | holdconn
}

// Secure reports whether the section's transport is an SRTP profile
// (RTP/SAVP, RTP/SAVPF, UDP/TLS/RTP/SAVP(F)).
func (a *Audio) Secure() bool {
	for _, p := range a.Proto {
		if p == "SAVP" || p == "SAVPF" {
			return true
		}
	}
	return false
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
	// Audio is the first audio m= section. Parse fails when there is none.
	Audio *Audio
	// SessionID and SessionVersion come from o=; the proxy reuses the ID
	// across re-offers on the same leg and bumps the version.
	SessionID      uint64
	SessionVersion uint64
	// Username is o=' first token, echoed so an endpoint that keys on it
	// sees something stable.
	Username string
	// MediaCount is how many m= sections the body had, including the ones
	// the proxy declines.
	MediaCount int
}

// Parse decodes and validates one SDP body.
func Parse(body []byte) (*Session, error) {
	if len(body) == 0 {
		return nil, errors.New("sdpx: empty body")
	}
	if len(body) > MaxSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooLarge, len(body), MaxSize)
	}
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(body); err != nil {
		return nil, fmt.Errorf("sdpx: parse: %w", err)
	}
	if len(sd.MediaDescriptions) > MaxMediaDescriptions {
		return nil, fmt.Errorf("%w: %d media sections", ErrTooLarge, len(sd.MediaDescriptions))
	}
	if len(sd.Attributes) > MaxAttributes {
		return nil, fmt.Errorf("%w: %d session attributes", ErrTooLarge, len(sd.Attributes))
	}

	var md *sdp.MediaDescription
	for _, m := range sd.MediaDescriptions {
		if len(m.Attributes) > MaxAttributes {
			return nil, fmt.Errorf("%w: %d media attributes", ErrTooLarge, len(m.Attributes))
		}
		// The FIRST audio section is the one relayed; a declined (port 0)
		// section is skipped so a body that offers a dead audio stream
		// followed by a live one still works.
		if md == nil && m.MediaName.Media == "audio" && m.MediaName.Port.Value != 0 {
			md = m
		}
	}
	if md == nil {
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
	if err := parseConnection(&sd, md, a); err != nil {
		return nil, err
	}
	parseAttributes(&sd, md, a)
	var err error
	if a.Codecs, err = parseCodecs(md); err != nil {
		return nil, err
	}
	if len(a.Codecs) == 0 {
		return nil, errors.New("sdpx: audio section has no payload types")
	}

	s := &Session{Audio: a, MediaCount: len(sd.MediaDescriptions), Username: sd.Origin.Username}
	s.SessionID, s.SessionVersion = sd.Origin.SessionID, sd.Origin.SessionVersion
	return s, nil
}

func parseConnection(sd *sdp.SessionDescription, md *sdp.MediaDescription, a *Audio) error {
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
	a.Address = ip.Unmap()
	return nil
}

// parseAttributes reads the session-level attributes first and then the
// media-level ones, so a media-level value overrides the session-level one
// per RFC 4566 §5.13.
func parseAttributes(sd *sdp.SessionDescription, md *sdp.MediaDescription, a *Audio) {
	apply := func(attrs []sdp.Attribute) {
		for _, at := range attrs {
			v := strings.TrimSpace(at.Value)
			switch at.Key {
			case "sendrecv", "sendonly", "recvonly", "inactive":
				a.Direction = Direction(at.Key)
			case "rtcp-mux":
				a.RTCPMux = true
			case "ice-lite":
				a.ICELite = true
			case "ice-ufrag":
				a.ICEUfrag = sanitizeICEToken(v)
			case "ice-pwd":
				a.ICEPwd = sanitizeICEToken(v)
			case "setup":
				switch v {
				case "active", "passive", "actpass", "holdconn":
					a.Setup = v
				}
			case "candidate":
				if len(a.Candidates) < MaxCandidates && validCandidate(v) {
					a.Candidates = append(a.Candidates, v)
				}
			case "fingerprint":
				if fp, ok := parseFingerprint(v); ok {
					a.Fingerprint = &fp
				}
			case "rtcp":
				// "a=rtcp:<port> [IN IP4 <addr>]" — only the port matters
				// to the proxy; the optional address is topology it must
				// not carry across.
				if p, err := strconv.Atoi(strings.Fields(v)[0]); err == nil && p > 0 && p < 65536 {
					a.RTCPPort = p
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
func parseCodecs(md *sdp.MediaDescription) ([]Codec, error) {
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
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("sdpx: bad payload type %q", f)
		}
		pt := uint8(n)
		if pt > 127 || seen[pt] {
			// >127 is outside the RTP payload-type space; a duplicate is
			// malformed. Skip rather than fail: the rest of the list may
			// still be a perfectly usable offer.
			continue
		}
		seen[pt] = true
		c := Codec{PayloadType: pt, FMTP: fmtp[pt]}
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
	if name == "" || len(name) > 64 {
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

// sanitizeICEToken keeps only the RFC 5245 ice-char set. An ICE ufrag or
// password is copied into the SDP the proxy generates for the other leg
// (and compared against STUN attributes), so anything outside the allowed
// alphabet — CR/LF above all — is dropped rather than echoed.
func sanitizeICEToken(v string) string {
	if len(v) < 4 || len(v) > 256 {
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

// validCandidate does a shape check on an a=candidate value. The proxy is
// ICE-Lite and never uses a remote candidate to send from (it always
// replies to the source of the connectivity check it accepted), so this is
// purely a "don't store attacker-shaped junk" gate, plus a defence against
// header injection when the value is echoed anywhere.
func validCandidate(v string) bool {
	if len(v) == 0 || len(v) > 512 {
		return false
	}
	if strings.ContainsAny(v, "\r\n") {
		return false
	}
	// foundation component transport priority address port typ <type> ...
	f := strings.Fields(v)
	return len(f) >= 8 && strings.EqualFold(f[6], "typ")
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

func isHexByte(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
