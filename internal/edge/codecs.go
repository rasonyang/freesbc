package edge

import (
	"strings"

	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// This file holds the proxy plane's codec POLICY: which audio codecs this
// SBC is willing to relay. It is deliberately not part of the sdp package,
// which knows how to parse, negotiate and render codecs but has no opinion
// about which ones a particular deployment carries.

// supportedCodecs lists the audio codecs the proxy will relay (spec §5).
// The list is deliberately closed: relaying a codec means committing to
// pass its payload through untouched, and anything not here is more likely
// a video/data payload smuggled into an audio section than a real offer.
//
// telephone-event is included so RFC 4733 DTMF survives the relay
// (spec §13); it is a payload the proxy carries, never one it interprets.
var supportedCodecs = map[string]bool{
	"pcmu":            true,
	"pcma":            true,
	"opus":            true,
	"telephone-event": true,
}

// codecSupported reports whether a codec name is relayable.
func codecSupported(name string) bool { return supportedCodecs[strings.ToLower(name)] }

// filterCodecs returns the codecs of in that the proxy can relay,
// preserving order and payload-type numbers. Order is the offerer's
// preference order and must survive: the answerer picks from the top.
func filterCodecs(in []sdp.Codec) []sdp.Codec {
	out := make([]sdp.Codec, 0, len(in))
	for _, c := range in {
		if codecSupported(c.Name) {
			out = append(out, c)
		}
	}
	return out
}
