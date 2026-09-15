package sdp

import (
	"fmt"
	"strings"
)

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

// Negotiate reduces an offer and the answer it received to the one codec
// list both ends will use, or fails the call.
//
// The result is in OFFER order, carrying the OFFER's payload-type numbers
// and the ANSWER's fmtp. Both choices matter and are the whole reason the
// proxy needs no transcoder:
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
// It fails with ErrNoCommonCodec when nothing usable is shared (a list
// that intersected down to telephone-event alone counts as nothing: it
// would "succeed" and then carry silence), and with ErrRenumbered when a
// codec both sides named sits on different payload numbers — some stacks
// renumber despite the RFC, and honouring that would mean rewriting the
// PT byte of every RTP packet.
func Negotiate(offer, answer []Codec) ([]Codec, error) {
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
		if a.PayloadType != o.PayloadType {
			return nil, fmt.Errorf("%w: offered %s, answered %s", ErrRenumbered, o, a)
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
