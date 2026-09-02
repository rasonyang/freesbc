package sdpx

import (
	"fmt"
	"strings"
)

// Supported lists the audio codecs the proxy will relay (spec §5). The
// list is deliberately closed: relaying a codec means committing to pass
// its payload through untouched, and anything not here is more likely a
// video/data payload smuggled into an audio section than a real offer.
//
// telephone-event is included so RFC 4733 DTMF survives the relay
// (spec §13); it is a payload the proxy carries, never one it interprets.
var Supported = map[string]bool{
	"pcmu":            true,
	"pcma":            true,
	"opus":            true,
	"telephone-event": true,
}

// IsSupported reports whether a codec name is relayable.
func IsSupported(name string) bool { return Supported[strings.ToLower(name)] }

// Filter returns the codecs of in that the proxy can relay, preserving
// order and payload-type numbers. Order is the offerer's preference order
// and must survive: the answerer picks from the top.
func Filter(in []Codec) []Codec {
	out := make([]Codec, 0, len(in))
	for _, c := range in {
		if IsSupported(c.Name) {
			out = append(out, c)
		}
	}
	return out
}

// HasMedia reports whether a codec list contains at least one codec that
// actually carries audio — telephone-event alone is not a call. Used to
// reject a negotiation that intersected down to DTMF only, which would
// otherwise "succeed" and then carry silence.
func HasMedia(in []Codec) bool {
	for _, c := range in {
		if !c.IsTelephoneEvent() {
			return true
		}
	}
	return false
}

// Intersect returns the codecs common to an offer and the answer it
// received, in OFFER order, carrying the OFFER's payload-type numbers and
// the ANSWER's fmtp.
//
// Both choices matter and are the whole reason the proxy needs no
// transcoder:
//
//   - Offer order and offer numbers: RFC 3264 §6 requires an answerer to
//     use the offerer's payload-type numbers, so the numbers in the offer
//     are the numbers on the wire in both directions. Emitting them
//     unchanged on the far leg is what lets the relay forward RTP without
//     touching the payload-type field of a single packet.
//   - Answer fmtp: the answerer is the side that narrowed the parameters
//     (opus ptime, maxaveragebitrate, the telephone-event range it will
//     actually generate). That narrowed form is what must reach the
//     original offerer.
//
// A codec whose payload NUMBER differs between the two lists is still
// matched — some stacks renumber despite the RFC — but the offer's number
// wins, and the caller can detect the disagreement via NeedsRenumber.
func Intersect(offer, answer []Codec) ([]Codec, error) {
	byKey := make(map[string]Codec, len(answer))
	for _, c := range answer {
		if _, dup := byKey[c.key()]; !dup {
			byKey[c.key()] = c
		}
	}
	var out []Codec
	for _, o := range offer {
		a, ok := byKey[o.key()]
		if !ok {
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

// NeedsRenumber reports the first codec whose payload-type number differs
// between the offer and the answer. The proxy cannot honour such an answer
// without rewriting the payload-type byte of every RTP packet, which is
// transcoding-adjacent work this phase does not do — the caller rejects
// the call instead of silently relaying packets the far side will misread.
func NeedsRenumber(offer, answer []Codec) (Codec, Codec, bool) {
	byKey := make(map[string]Codec, len(answer))
	for _, c := range answer {
		if _, dup := byKey[c.key()]; !dup {
			byKey[c.key()] = c
		}
	}
	for _, o := range offer {
		if a, ok := byKey[o.key()]; ok && a.PayloadType != o.PayloadType {
			return o, a, true
		}
	}
	return Codec{}, Codec{}, false
}

// Describe renders a codec list for logs. Used in error messages, so it
// must stay free of anything an attacker could use to forge a log line:
// codec names are alphanumeric by construction (parseRTPMap rejects the
// rest) and fmtp is not included.
func Describe(cs []Codec) string {
	if len(cs) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, ", ")
}
