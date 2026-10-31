package sdp

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Build describes the SDP body the proxy wants to emit on one leg. Every
// field is something the proxy itself decides: the address and ports are
// its own sockets, the codec list is the negotiated one, and the ICE/DTLS
// block is present only for a browser-facing leg.
//
// What is deliberately NOT here is anything copied from the other leg's
// body. Construction is from scratch, which is what guarantees the two
// leaks the spec forbids cannot happen (§10, acceptance #9/#10): a private
// FreeSWITCH address can never appear in a public body because no public
// body is ever derived from a private one, and browser ICE candidates can
// never reach FreeSWITCH because nothing copies them.
type Build struct {
	// Address is the c=/o= address: the SBC's advertised address on THIS
	// leg's plane.
	Address netip.Addr
	// Port is the RTP port of the SBC socket serving this leg.
	Port int
	// Codecs is the negotiated list, in preference order, carrying the
	// payload-type numbers both sides will see on the wire.
	Codecs []Codec
	// Direction is this leg's media direction.
	Direction Direction

	// SessionID/SessionVersion go into o=. A re-offer on the same leg must
	// reuse the ID and bump the version.
	SessionID      uint64
	SessionVersion uint64

	// --- WebRTC-only fields. All zero for a plain RTP leg. ---

	// DTLS turns on the browser-facing block: the UDP/TLS/RTP/SAVPF
	// profile, ICE-Lite credentials, a host candidate at Address:Port, the
	// certificate fingerprint and the DTLS role. SDES (see Crypto) is the
	// other secure profile.
	DTLS bool
	// RTCPMux writes a=rtcp-mux.
	RTCPMux     bool
	ICEUfrag    string
	ICEPwd      string
	Fingerprint *Fingerprint
	// Setup is the DTLS role this side takes: "passive" when the proxy is
	// the DTLS server (the normal answer to a browser's actpass), "active"
	// when it is the client, and "actpass" in the proxy's own initial
	// offer to a browser, which leaves the choice to the answerer.
	Setup string

	// --- SDES-only field. Empty for a plain RTP leg. ---

	// Crypto turns on SDES: the transport becomes RTP/SAVP and each entry
	// is written as an a=crypto line, in order. An offer carries one line
	// per suite offered; an answer exactly one, with the selected tag.
	// Mutually exclusive with DTLS. Plain and DTLS output is unchanged
	// when it is empty.
	Crypto []Crypto
}

// Marshal renders the body.
//
// The result always has exactly one media section — the audio the proxy
// relays. A multi-section offer is answered by declining the rest, which
// MarshalDeclining does; callers that must preserve the section count use it
// instead.
func (b Build) Marshal() ([]byte, error) { return b.marshal(nil) }

// MarshalDeclining renders the body as an answer to offer: one m= line per
// offered section, in the offer's order (RFC 3264 §6). The relayed audio
// section sits at offer.AudioIndex; every other section is declined at
// port 0 with the offer's media type and transport, so a video-first offer
// is answered video (declined), audio (live).
//
// The declined sections carry no attributes and no connection line: a
// declined section's contents are moot, and clearing them is what keeps a
// peer's keys, candidates and addresses from riding along. Their format is
// a fixed placeholder chosen by transport, never the offer's.
//
// A Session not produced by Parse may carry only MediaCount; its sections
// are then taken to be RTP/AVP audio with the live one first.
func (b Build) MarshalDeclining(offer *Session) ([]byte, error) {
	if offer == nil {
		return b.marshal(nil)
	}
	if len(offer.Sections) == 0 && offer.MediaCount > 1 {
		o := *offer
		o.AudioIndex = 0
		o.Sections = make([]Section, offer.MediaCount)
		for i := range o.Sections {
			o.Sections[i] = Section{Media: "audio", Proto: []string{"RTP", "AVP"}}
		}
		offer = &o
	}
	if len(offer.Sections) <= 1 || offer.AudioIndex < 0 || offer.AudioIndex >= len(offer.Sections) {
		return b.marshal(nil)
	}
	return b.marshal(offer)
}

func (b Build) marshal(offer *Session) ([]byte, error) {
	if !b.Address.IsValid() {
		return nil, fmt.Errorf("sdp: build: no advertised address")
	}
	if b.Port <= 0 || b.Port > 65535 {
		return nil, fmt.Errorf("sdp: build: bad port %d", b.Port)
	}
	if len(b.Codecs) == 0 {
		return nil, ErrNoCommonCodec
	}
	if b.DTLS && (b.Fingerprint == nil || b.ICEUfrag == "" || b.ICEPwd == "") {
		return nil, fmt.Errorf("sdp: build: DTLS leg needs a fingerprint and ICE credentials")
	}

	if len(b.Crypto) > 0 {
		if b.DTLS {
			return nil, fmt.Errorf("sdp: build: SDES and DTLS are mutually exclusive")
		}
		if len(b.Crypto) > MaxCrypto {
			return nil, fmt.Errorf("sdp: build: %d crypto lines", len(b.Crypto))
		}
		for _, c := range b.Crypto {
			if err := c.Validate(); err != nil {
				return nil, fmt.Errorf("sdp: build: %w", err)
			}
		}
	}

	addrType := AddrType(b.Address)
	dir := b.Direction
	if dir == "" {
		dir = SendRecv
	}

	// The body is written straight into one buffer sized up front. The
	// layout is exactly what pion/sdp's marshaller produced from the
	// structs this function used to build (TestBuildMatchesPionReference
	// keeps that implementation as the reference): every line ends CRLF,
	// an attribute with an empty value is written without a colon, and
	// lists are joined the way pion joins them.
	buf := make([]byte, 0, b.sizeHint(offer, len(dir)))
	buf = append(buf, "v=0\r\no=FreeSBC "...)
	buf = strconv.AppendUint(buf, b.SessionID, 10)
	buf = append(buf, ' ')
	buf = strconv.AppendUint(buf, b.SessionVersion, 10)
	buf = append(buf, " IN "...)
	buf = append(buf, addrType...)
	buf = append(buf, ' ')
	buf = b.Address.AppendTo(buf)
	buf = append(buf, "\r\ns=FreeSBC\r\nc=IN "...)
	buf = append(buf, addrType...)
	buf = append(buf, ' ')
	buf = b.Address.AppendTo(buf)
	buf = append(buf, "\r\nt=0 0\r\n"...)
	if offer == nil {
		return b.appendAudio(buf, string(dir)), nil
	}
	for i, sec := range offer.Sections {
		if i == offer.AudioIndex {
			buf = b.appendAudio(buf, string(dir))
		} else {
			buf = appendDeclined(buf, sec)
		}
	}
	return buf, nil
}

// appendAudio writes the live audio m= section.
func (b Build) appendAudio(buf []byte, dir string) []byte {
	buf = append(buf, "m=audio "...)
	buf = strconv.AppendInt(buf, int64(b.Port), 10)
	buf = append(buf, ' ')
	buf = append(buf, b.proto()...)
	buf = append(buf, ' ')
	for i, c := range b.Codecs {
		if i > 0 {
			buf = append(buf, ' ')
		}
		buf = strconv.AppendUint(buf, uint64(c.PayloadType), 10)
	}
	buf = append(buf, "\r\n"...)

	// ICE/DTLS block first (that is the conventional order a browser
	// expects to read), then rtpmap/fmtp, then direction and rtcp.
	if b.DTLS {
		buf = append(buf, "a=ice-lite\r\n"...)
		buf = appendAttr(buf, "ice-ufrag", b.ICEUfrag)
		buf = appendAttr(buf, "ice-pwd", b.ICEPwd)
		// One host candidate at our stable public media address is the
		// whole candidate set an ICE-Lite agent has (RFC 5245 §4.2).
		// Component 1 only: rtcp-mux means there is no component 2.
		buf = append(buf, "a=candidate:1 1 UDP "...)
		buf = strconv.AppendInt(buf, iceLitePriority, 10)
		buf = append(buf, ' ')
		buf = b.Address.AppendTo(buf)
		buf = append(buf, ' ')
		buf = strconv.AppendInt(buf, int64(b.Port), 10)
		buf = append(buf, " typ host\r\na=end-of-candidates\r\na=fingerprint:"...)
		buf = append(buf, b.Fingerprint.Hash...)
		buf = append(buf, ' ')
		buf = append(buf, b.Fingerprint.Value...)
		buf = append(buf, "\r\n"...)
		buf = appendAttr(buf, "setup", b.Setup)
	}
	for _, c := range b.Codecs {
		buf = append(buf, "a=rtpmap:"...)
		buf = strconv.AppendUint(buf, uint64(c.PayloadType), 10)
		buf = append(buf, ' ')
		buf = append(buf, c.Name...)
		buf = append(buf, '/')
		buf = strconv.AppendUint(buf, uint64(c.ClockRate), 10)
		if c.Channels > 1 {
			buf = append(buf, '/')
			buf = strconv.AppendInt(buf, int64(c.Channels), 10)
		}
		buf = append(buf, "\r\n"...)
		// Filtered again here, not only in Parse: a Codec may have been
		// built by the caller, and the emitted text must be this package's
		// own rendering whatever its origin.
		if f := canonicalFMTP(c.Name, c.FMTP); f != "" {
			buf = append(buf, "a=fmtp:"...)
			buf = strconv.AppendUint(buf, uint64(c.PayloadType), 10)
			buf = append(buf, ' ')
			buf = append(buf, f...)
			buf = append(buf, "\r\n"...)
		}
	}
	for _, c := range b.Crypto {
		buf = append(buf, "a=crypto:"...)
		buf = c.appendValue(buf)
		buf = append(buf, "\r\n"...)
	}
	buf = appendAttr(buf, dir, "")
	if b.RTCPMux {
		buf = append(buf, "a=rtcp-mux\r\n"...)
	}
	// No a=rtcp line otherwise: RTCP rides the RFC 3550 default of RTP+1,
	// and stating it explicitly only invites disagreement.
	// ptime is not emitted: the proxy does not repacketize, so claiming a
	// packetization interval it does not enforce would be a lie the far
	// side could act on.
	return buf
}

// appendAttr writes one a= line: "a=key:value", or "a=key" when value is
// empty.
func appendAttr(buf []byte, key, value string) []byte {
	buf = append(buf, "a="...)
	buf = append(buf, key...)
	if value != "" {
		buf = append(buf, ':')
		buf = append(buf, value...)
	}
	return append(buf, "\r\n"...)
}

// sizeHint is an upper bound on the body's length for the usual inputs,
// so the buffer is allocated once; an underestimate only costs a regrow.
// The constants are each line's fixed text plus the widest number it can
// carry.
func (b Build) sizeHint(offer *Session, dirLen int) int {
	addr := 15 // dotted IPv4
	if !b.Address.Is4() {
		addr = 39 + 1 + len(b.Address.Zone())
	}
	// v=, o=, s=, c=, t= and the audio m= line without its formats.
	n := 5 + (10 + 20 + 1 + 20 + 8 + addr + 2) + 11 + (9 + addr + 2) + 7 + (8 + 5 + 1 + 17 + 1 + 2)
	n += 4 + dirLen + 12 // direction, rtcp-mux
	for _, c := range b.Codecs {
		n += 4                                // format
		n += 9 + 3 + 1 + len(c.Name) + 22 + 2 // rtpmap
		if c.FMTP != "" {
			n += 7 + 3 + 1 + len(c.FMTP) + 2
		}
	}
	for _, c := range b.Crypto {
		n += 9 + 20 + 1 + len(c.Suite) + 8 + base64.StdEncoding.EncodedLen(len(c.Key)+len(c.Salt)) + 2
	}
	if b.DTLS {
		n += 12 + (14 + len(b.ICEUfrag)) + (12 + len(b.ICEPwd)) + (48 + addr) + 21 + (10 + len(b.Setup))
		if b.Fingerprint != nil {
			n += 14 + len(b.Fingerprint.Hash) + 1 + len(b.Fingerprint.Value) + 2
		}
	}
	if offer != nil {
		for _, sec := range offer.Sections {
			n += 2 + len(sec.Media) + 3 + 18 + 2
			for _, p := range sec.Proto {
				n += 1 + len(p)
			}
		}
	}
	return n
}

// iceLitePriority is the priority of the single host candidate an ICE-Lite
// agent offers. RFC 5245 §4.1.2.1 computes it as
// (2^24)*type_pref + (2^8)*local_pref + (256 - component), with type
// preference 126 for host, local preference 65535 for the only candidate,
// component 1.
const iceLitePriority = 126<<24 | 65535<<8 | (256 - 1)

// proto is the audio section's transport.
func (b Build) proto() string {
	if b.DTLS {
		// SAVPF (RFC 5124) is what every browser offers and answers.
		return "UDP/TLS/RTP/SAVPF"
	}
	if len(b.Crypto) > 0 {
		return "RTP/SAVP"
	}
	return "RTP/AVP"
}

// appendDeclined writes an RFC 3264 §6 rejected stream: the offered media
// type and transport, port 0, no attributes, no connection information.
func appendDeclined(buf []byte, sec Section) []byte {
	buf = append(buf, "m="...)
	buf = append(buf, sec.Media...)
	buf = append(buf, " 0 "...)
	for i, p := range sec.Proto {
		if i > 0 {
			buf = append(buf, '/')
		}
		buf = append(buf, p...)
	}
	buf = append(buf, ' ')
	buf = append(buf, placeholderFormat(sec.Proto)...)
	return append(buf, "\r\n"...)
}

// placeholderFormat is the fmt token a declined m= line carries. RFC 4566
// requires at least one; its value is moot for a rejected stream, so it is
// a constant per transport family rather than the offer's list.
func placeholderFormat(proto []string) string {
	switch p := strings.Join(proto, "/"); p {
	case "UDP/DTLS/SCTP", "TCP/DTLS/SCTP":
		return "webrtc-datachannel"
	case "DTLS/SCTP":
		return "5000"
	case "udptl":
		return "t38"
	case "TCP/MSRP", "TCP/TLS/MSRP", "UDP/BFCP", "TCP/BFCP", "TCP/TLS/BFCP", "TCP", "UDP":
		return "*"
	}
	return "0"
}

// AddrType is the RFC 4566 addrtype token for an address, as it appears in
// o= and c= lines.
func AddrType(ip netip.Addr) string {
	if ip.Is6() {
		return "IP6"
	}
	return "IP4"
}
