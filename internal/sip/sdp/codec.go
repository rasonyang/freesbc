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
//   - Offer order and offer numbers: RFC 3264 §6.1 says an answerer SHOULD
//     use the offerer's payload-type numbers (a recommendation, not a
//     requirement), and when it does the numbers in the offer are the
//     numbers on the wire in both directions. Emitting them unchanged on
//     the far leg is what lets the relay forward RTP without touching the
//     payload-type field of a single packet.
//   - Answer fmtp: the answerer is the side that narrowed the parameters
//     (opus ptime, maxaveragebitrate, the telephone-event range it will
//     actually generate). That narrowed form is what must reach the
//     original offerer.
//
// It fails with ErrNoCommonCodec when nothing usable is shared (a list
// that intersected down to telephone-event alone counts as nothing: it
// would "succeed" and then carry silence), and with ErrRenumbered when a
// codec both sides named sits on different payload numbers — some stacks
// use the SHOULD's latitude to renumber, and honouring that would mean
// rewriting the PT byte of every RTP packet. Refusing is this package's
// policy, not an RFC requirement.
func Negotiate(offer, answer []Codec) ([]Codec, error) {
	// One encoding may sit on several payload numbers in an offer
	// (RFC 3264 §6.1: opus on 111 and on 96 with other parameters), so a
	// codec is matched by its offered number first. An answer codec is
	// renumbered only when its encoding was offered and none of the
	// numbers the offer gave that encoding is the one it answered on.
	//
	// Codec lists are short (Parse caps them at MaxCodecs), so the offer
	// is scanned linearly and the answer accepted on each payload number
	// is kept in a fixed table: no map and no key string per codec.
	var byPT [256]int32 // 1 + index in answer of the codec accepted on that PT; 0 = none
	for i, a := range answer {
		at, enc := offered(offer, a)
		if at {
			if byPT[a.PayloadType] == 0 {
				byPT[a.PayloadType] = int32(i) + 1
			}
			continue
		}
		if enc {
			return nil, fmt.Errorf("%w: offered %s, answered %s", ErrRenumbered, Describe(offerOf(offer, a)), a)
		}
	}
	// Count first so the result is one exact allocation, made only on
	// success.
	n, media := 0, false
	for _, o := range offer {
		if a, ok := acceptedOn(answer, &byPT, o); ok && a.sameEncoding(o) {
			n++
			media = media || !o.IsTelephoneEvent()
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: offer %s vs answer %s", ErrNoCommonCodec, Describe(offer), Describe(answer))
	}
	if !media {
		return nil, fmt.Errorf("%w: only telephone-event in common", ErrNoCommonCodec)
	}
	out := make([]Codec, 0, n)
	for _, o := range offer {
		a, ok := acceptedOn(answer, &byPT, o)
		if !ok || !a.sameEncoding(o) {
			continue
		}
		merged := o
		merged.FMTP = a.FMTP
		out = append(out, merged)
	}
	return out, nil
}

// offered reports whether the offer has a's encoding on a's payload
// number (at), and whether it has a's encoding at all (enc).
func offered(offer []Codec, a Codec) (at, enc bool) {
	for _, o := range offer {
		if o.sameEncoding(a) {
			enc = true
			if o.PayloadType == a.PayloadType {
				return true, true
			}
		}
	}
	return false, enc
}

// acceptedOn is the answer codec Negotiate accepted on o's payload number.
func acceptedOn(answer []Codec, byPT *[256]int32, o Codec) (Codec, bool) {
	i := byPT[o.PayloadType]
	if i == 0 {
		return Codec{}, false
	}
	return answer[i-1], true
}

// offerOf is the offered codecs of a's encoding, for the renumber error.
func offerOf(offer []Codec, a Codec) []Codec {
	var out []Codec
	for _, o := range offer {
		if o.sameEncoding(a) {
			out = append(out, o)
		}
	}
	return out
}

// Describe renders a codec list for logs. Used in error messages, so it
// must stay free of anything an attacker could use to forge a log line:
// a parsed codec name is letters, digits, '-', '_' and '.' only
// (validEncodingName, enforced by parseRTPMap) and fmtp is not included.
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
