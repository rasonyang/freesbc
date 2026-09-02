package sdp

import (
	"fmt"
	"net/netip"
	"strconv"

	// pion's package is also called sdp; alias it so this package can
	// keep the name that reads best at its own call sites.
	pionsdp "github.com/pion/sdp/v3"
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
	// RTCPPort, when non-zero and different from Port+1, is written as
	// a=rtcp. Ignored when RTCPMux is set.
	RTCPPort int
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

	// Secure selects an SRTP profile. With DTLS set, the profile is
	// UDP/TLS/RTP/SAVPF; without it, RTP/SAVP (SDES is not generated here
	// — the trunk plane owns that).
	Secure bool
	// DTLS turns on the browser-facing block: ICE-Lite credentials,
	// a host candidate at Address:Port, the certificate fingerprint and
	// the DTLS role.
	DTLS bool
	// RTCPMux writes a=rtcp-mux.
	RTCPMux     bool
	ICEUfrag    string
	ICEPwd      string
	Fingerprint *Fingerprint
	// Setup is the DTLS role this side takes: "passive" when the proxy is
	// the DTLS server (the normal answer to a browser's actpass), "active"
	// when it is the client.
	Setup string
}

// Marshal renders the body.
//
// The result always has exactly one media section — the audio the proxy
// relays. A multi-section offer is answered by declining the rest, which
// Decline builds; callers that must preserve the section count use
// MarshalDeclining instead.
func (b Build) Marshal() ([]byte, error) { return b.marshal(0) }

// MarshalDeclining renders the body with (extra) additional audio/video/
// application sections declined at port 0, so the section count and order
// of an offer are preserved as RFC 3264 §6 requires of an answer. The
// declined sections carry no attributes and no connection line: a declined
// section's contents are moot, and clearing them is what keeps a peer's
// keys, candidates and addresses from riding along.
func (b Build) MarshalDeclining(offer *Session) ([]byte, error) {
	extra := 0
	if offer != nil && offer.MediaCount > 1 {
		extra = offer.MediaCount - 1
	}
	return b.marshal(extra)
}

func (b Build) marshal(declined int) ([]byte, error) {
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

	addrType := "IP4"
	if b.Address.Is6() {
		addrType = "IP6"
	}
	conn := &pionsdp.ConnectionInformation{
		NetworkType: "IN",
		AddressType: addrType,
		Address:     &pionsdp.Address{Address: b.Address.String()},
	}
	sd := &pionsdp.SessionDescription{
		Version: 0,
		Origin: pionsdp.Origin{
			Username:       "FreeSBC",
			SessionID:      b.SessionID,
			SessionVersion: b.SessionVersion,
			NetworkType:    "IN",
			AddressType:    addrType,
			UnicastAddress: b.Address.String(),
		},
		SessionName:           "FreeSBC",
		ConnectionInformation: conn,
		TimeDescriptions:      []pionsdp.TimeDescription{{Timing: pionsdp.Timing{StartTime: 0, StopTime: 0}}},
	}

	md := &pionsdp.MediaDescription{
		MediaName: pionsdp.MediaName{
			Media:  "audio",
			Port:   pionsdp.RangedPort{Value: b.Port},
			Protos: b.protos(),
		},
	}
	for _, c := range b.Codecs {
		md.MediaName.Formats = append(md.MediaName.Formats, strconv.Itoa(int(c.PayloadType)))
	}

	// ICE/DTLS block first (that is the conventional order a browser
	// expects to read), then rtpmap/fmtp, then direction and rtcp.
	if b.DTLS {
		md.Attributes = append(md.Attributes,
			attr("ice-lite", ""),
			attr("ice-ufrag", b.ICEUfrag),
			attr("ice-pwd", b.ICEPwd),
			// One host candidate at our stable public media address is the
			// whole candidate set an ICE-Lite agent has (RFC 5245 §4.2).
			// Component 1 only: rtcp-mux means there is no component 2.
			attr("candidate", fmt.Sprintf("1 1 UDP %d %s %d typ host", iceLitePriority, b.Address.String(), b.Port)),
			attr("end-of-candidates", ""),
			attr("fingerprint", b.Fingerprint.String()),
			attr("setup", b.Setup),
		)
	}
	for _, c := range b.Codecs {
		md.Attributes = append(md.Attributes, attr("rtpmap", rtpmapValue(c)))
		if c.FMTP != "" {
			md.Attributes = append(md.Attributes, attr("fmtp", fmt.Sprintf("%d %s", c.PayloadType, c.FMTP)))
		}
	}
	dir := b.Direction
	if dir == "" {
		dir = SendRecv
	}
	md.Attributes = append(md.Attributes, attr(string(dir), ""))
	if b.RTCPMux {
		md.Attributes = append(md.Attributes, attr("rtcp-mux", ""))
	} else if b.RTCPPort != 0 && b.RTCPPort != b.Port+1 {
		// Only worth stating when it is not the RFC 3550 default of
		// RTP+1; an explicit line otherwise just invites disagreement.
		md.Attributes = append(md.Attributes, attr("rtcp", strconv.Itoa(b.RTCPPort)))
	}
	// ptime is not emitted: the proxy does not repacketize, so claiming a
	// packetization interval it does not enforce would be a lie the far
	// side could act on.
	sd.MediaDescriptions = append(sd.MediaDescriptions, md)

	for i := 0; i < declined; i++ {
		sd.MediaDescriptions = append(sd.MediaDescriptions, declinedSection())
	}
	return sd.Marshal()
}

// iceLitePriority is the priority of the single host candidate an ICE-Lite
// agent offers. RFC 5245 §4.1.2.1 computes it as
// (2^24)*type_pref + (2^8)*local_pref + (256 - component), with type
// preference 126 for host, local preference 65535 for the only candidate,
// component 1.
const iceLitePriority = 126<<24 | 65535<<8 | (256 - 1)

func (b Build) protos() []string {
	switch {
	case b.DTLS:
		// SAVPF (RFC 5124) is what every browser offers and answers.
		return []string{"UDP", "TLS", "RTP", "SAVPF"}
	case b.Secure:
		return []string{"RTP", "SAVP"}
	default:
		return []string{"RTP", "AVP"}
	}
}

func rtpmapValue(c Codec) string {
	if c.Channels > 1 {
		return fmt.Sprintf("%d %s/%d/%d", c.PayloadType, c.Name, c.ClockRate, c.Channels)
	}
	return fmt.Sprintf("%d %s/%d", c.PayloadType, c.Name, c.ClockRate)
}

func attr(k, v string) pionsdp.Attribute { return pionsdp.Attribute{Key: k, Value: v} }

// declinedSection is an RFC 3264 §6 rejected stream: port 0, no
// attributes, no connection information.
func declinedSection() *pionsdp.MediaDescription {
	return &pionsdp.MediaDescription{
		MediaName: pionsdp.MediaName{
			Media:   "audio",
			Port:    pionsdp.RangedPort{Value: 0},
			Protos:  []string{"RTP", "AVP"},
			Formats: []string{"0"},
		},
	}
}
