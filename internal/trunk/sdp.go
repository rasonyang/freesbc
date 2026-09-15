package trunk

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/freesbc/freesbc/internal/media"
	fsdp "github.com/freesbc/freesbc/internal/sip/sdp"
	"github.com/pion/sdp/v3"
)

// remoteMediaIP returns the connection address the peer expects media from:
// the first relayable audio media description's media-level c= if present,
// otherwise the session-level c=. Used to arm the media latch.
//
// The parse is pion/sdp directly, not the proxy plane's bounded sdp.Parse:
// the trunk is a byte relay between carriers and must not reject a body
// the far side would have accepted (a payload type with no a=rtpmap, a
// large body, many m= sections). Its own rewrite is what bounds what
// crosses the bridge.
func remoteMediaIP(sdpBytes []byte) (netip.Addr, error) {
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(sdpBytes); err != nil {
		return netip.Addr{}, fmt.Errorf("parse sdp: %w", err)
	}
	md := firstAudio(&sd)
	if md == nil {
		return netip.Addr{}, fmt.Errorf("sdp has no audio media")
	}
	conn := md.ConnectionInformation
	if conn == nil {
		conn = sd.ConnectionInformation
	}
	if conn == nil || conn.Address == nil {
		return netip.Addr{}, fmt.Errorf("sdp has no connection address")
	}
	ip, err := netip.ParseAddr(conn.Address.Address)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("bad connection address %q: %w", conn.Address.Address, err)
	}
	return ip, nil
}

// validAudioSDP reports whether body is an SDP the bridge can relay: it
// parses and carries at least one live audio m= section. It is the
// target-independent half of what rewriteSDPCrypto would reject, checked
// once up front in placeCall so the same offer doesn't fail identically on
// every failover attempt.
//
// Trunk-local rules only, for the same reason as remoteMediaIP: nothing
// here may reject a body on codec or size policy the peers agreed between
// themselves.
func validAudioSDP(body []byte) error {
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(body); err != nil {
		return fmt.Errorf("parse sdp: %w", err)
	}
	if firstAudio(&sd) == nil {
		return fmt.Errorf("sdp has no audio media")
	}
	return nil
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

// offeredCrypto reports whether the first audio section is SRTP (proto
// RTP/SAVP) and returns its parsed, supported a=crypto lines (empty if none).
func offeredCrypto(sdpBytes []byte) (secure bool, lines []cryptoLine) {
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(sdpBytes); err != nil {
		return false, nil
	}
	md := firstAudio(&sd)
	if md == nil {
		return false, nil
	}
	isSAVP := false
	for _, p := range md.MediaName.Protos {
		if p == "SAVP" {
			isSAVP = true
		}
	}
	var values []string
	for _, a := range md.Attributes {
		if a.Key == "crypto" {
			values = append(values, a.Value)
		}
	}
	return isSAVP, parseCryptoAttrs(values)
}

// rewriteSDPCrypto points the SDP at our media and is SRTP-aware: the relayed audio
// section's proto becomes RTP/SAVP with one a=crypto (tagged crypto.tag) when
// crypto != nil, or RTP/AVP with all a=crypto stripped when nil. Topology
// hiding rewrites o=, the session-level c= and the relayed audio port (plus
// a=rtcp) to our own; every declined (non-relayed) media section is zeroed
// per RFC 3264 and has its attributes cleared entirely (md.Attributes =
// nil), not just its connection info, and any session-level a=crypto is
// stripped too.
// This closes a key-exposure bug: an SDES offerer commonly reuses ONE master
// key across every m= line in the SDP, so a declined section's a=crypto (or
// a session-level a=crypto that applies to it) would otherwise carry the
// SAME key as the relayed section straight through to the other leg, even
// though that section's own media never crosses the bridge. A port-0
// section is rejected per RFC 3264 §6, so its attributes are moot to relay
// in the first place — clearing them is free and also closes the
// pre-existing a=rtcp/candidate address leak. Applied unconditionally, on
// both the secure and plaintext (crypto == nil) paths: a declined section
// leaks the peer's live key regardless of whether the relayed section itself
// ends up secure.
func rewriteSDPCrypto(sdpBytes []byte, mediaIP netip.Addr, rtpPort int, crypto *sdpCrypto) ([]byte, error) {
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(sdpBytes); err != nil {
		return nil, fmt.Errorf("parse sdp: %w", err)
	}
	relayMD := firstAudio(&sd)
	if relayMD == nil {
		return nil, fmt.Errorf("sdp has no audio media")
	}
	addr := &sdp.Address{Address: mediaIP.String()}
	sd.ConnectionInformation = &sdp.ConnectionInformation{NetworkType: "IN", AddressType: fsdp.AddrType(mediaIP), Address: addr}
	sd.Origin.NetworkType = "IN"
	sd.Origin.AddressType = fsdp.AddrType(mediaIP)
	sd.Origin.UnicastAddress = mediaIP.String()

	for _, md := range sd.MediaDescriptions {
		if md == relayMD {
			md.MediaName.Port = sdp.RangedPort{Value: rtpPort}
			md.ConnectionInformation = nil
			// proto + crypto
			if crypto != nil {
				md.MediaName.Protos = []string{"RTP", "SAVP"}
			} else {
				md.MediaName.Protos = []string{"RTP", "AVP"}
			}
			// rebuild attributes: keep everything except crypto/rtcp handling,
			// drop any inbound a=crypto, then add ours if secure.
			var attrs []sdp.Attribute
			for _, a := range md.Attributes {
				if a.Key == "crypto" {
					continue // never echo the peer's key
				}
				if a.Key == "rtcp" {
					a.Value = strconv.Itoa(rtpPort + 1)
				}
				attrs = append(attrs, a)
			}
			if crypto != nil {
				attrs = append(attrs, sdp.Attribute{Key: "crypto",
					Value: cryptoAttrValue(crypto.tag, crypto.suite, crypto.keyValue)})
			}
			md.Attributes = attrs
			continue
		}
		// Declined section: port 0 and no connection info per RFC 3264, plus
		// every attribute cleared — see this function's doc comment for why
		// a=crypto here is a key leak, not just topology.
		md.MediaName.Port = sdp.RangedPort{Value: 0}
		md.ConnectionInformation = nil
		md.Attributes = nil
	}
	// Session-level a=crypto (rare, but SDES allows it) would otherwise
	// leak the peer's key straight through unfiltered — strip it same as
	// any media-level one.
	if len(sd.Attributes) > 0 {
		var sessionAttrs []sdp.Attribute
		for _, a := range sd.Attributes {
			if a.Key == "crypto" {
				continue
			}
			sessionAttrs = append(sessionAttrs, a)
		}
		sd.Attributes = sessionAttrs
	}
	out, err := sd.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal sdp: %w", err)
	}
	return out, nil
}

// firstAudio is the one audio section the bridge relays: the first
// "m=audio" whose port is non-zero. A port-0 section is declined by the
// peer (RFC 3264 §6) and carries no media, so skipping it here is what
// keeps the latch address (remoteMediaIP) and the section rewriteSDPCrypto
// actually relays pointing at the same m= line.
func firstAudio(sd *sdp.SessionDescription) *sdp.MediaDescription {
	for _, md := range sd.MediaDescriptions {
		if md.MediaName.Media == "audio" && md.MediaName.Port.Value != 0 {
			return md
		}
	}
	return nil
}
