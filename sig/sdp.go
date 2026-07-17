package sig

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/freesbc/freesbc/media"
	"github.com/pion/sdp/v3"
)

// remoteMediaIP returns the connection address the peer expects media from:
// the first audio media description's media-level c= if present, otherwise
// the session-level c=. Used to arm the media latch.
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

// rewriteSDP points the SDP at our media, hiding the peer's topology from
// the other side of the bridge: the o= origin and session-level c= become
// ourIP, the first audio m= port becomes rtpPort (a=rtcp, if present,
// becomes rtpPort+1), and every other media section (additional audio,
// video, application/T.38, etc.) is declined by zeroing its port and
// stripping any media-level c= per RFC 3264. It returns the re-marshalled
// SDP. Errors on unparseable input or SDP with no audio media.
func rewriteSDP(sdpBytes []byte, ourIP netip.Addr, rtpPort int) ([]byte, error) {
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(sdpBytes); err != nil {
		return nil, fmt.Errorf("parse sdp: %w", err)
	}
	if firstAudio(&sd) == nil {
		return nil, fmt.Errorf("sdp has no audio media")
	}
	addr := &sdp.Address{Address: ourIP.String()}
	sd.ConnectionInformation = &sdp.ConnectionInformation{
		NetworkType: "IN",
		AddressType: sdpAddrType(ourIP),
		Address:     addr,
	}
	sd.Origin.NetworkType = "IN"
	sd.Origin.AddressType = sdpAddrType(ourIP)
	sd.Origin.UnicastAddress = ourIP.String()

	relayed := false
	for _, md := range sd.MediaDescriptions {
		if !relayed && md.MediaName.Media == "audio" {
			md.MediaName.Port = sdp.RangedPort{Value: rtpPort}
			// Drop any media-level c= so the session-level one governs.
			md.ConnectionInformation = nil
			for i := range md.Attributes {
				if md.Attributes[i].Key == "rtcp" {
					md.Attributes[i].Value = strconv.Itoa(rtpPort + 1)
				}
			}
			relayed = true
			continue
		}
		// Not the relayed audio section: decline it (RFC 3264 port 0) and
		// strip any media-level c= so it can't leak the peer's address.
		md.MediaName.Port = sdp.RangedPort{Value: 0}
		md.ConnectionInformation = nil
	}
	out, err := sd.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal sdp: %w", err)
	}
	return out, nil
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

// rewriteSDPCrypto is rewriteSDP plus SRTP awareness: the relayed audio
// section's proto becomes RTP/SAVP with one a=crypto (tagged crypto.tag) when
// crypto != nil, or RTP/AVP with all a=crypto stripped when nil. Topology
// hiding (o=/c=/port) is identical to rewriteSDP, but declined sections go
// further here than in rewriteSDP: every declined (non-relayed) media
// section has its attributes cleared entirely (md.Attributes = nil), not
// just its connection info, and any session-level a=crypto is stripped too.
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
func rewriteSDPCrypto(sdpBytes []byte, ourIP netip.Addr, rtpPort int, crypto *sdpCrypto) ([]byte, error) {
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(sdpBytes); err != nil {
		return nil, fmt.Errorf("parse sdp: %w", err)
	}
	if firstAudio(&sd) == nil {
		return nil, fmt.Errorf("sdp has no audio media")
	}
	addr := &sdp.Address{Address: ourIP.String()}
	sd.ConnectionInformation = &sdp.ConnectionInformation{NetworkType: "IN", AddressType: sdpAddrType(ourIP), Address: addr}
	sd.Origin.NetworkType = "IN"
	sd.Origin.AddressType = sdpAddrType(ourIP)
	sd.Origin.UnicastAddress = ourIP.String()

	relayed := false
	for _, md := range sd.MediaDescriptions {
		if !relayed && md.MediaName.Media == "audio" {
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
			relayed = true
			continue
		}
		// Declined section: port 0 and no connection info per RFC 3264, plus
		// (unlike plain rewriteSDP) every attribute cleared — see this
		// function's doc comment for why a=crypto here is a key leak, not
		// just topology.
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

func firstAudio(sd *sdp.SessionDescription) *sdp.MediaDescription {
	for _, md := range sd.MediaDescriptions {
		if md.MediaName.Media == "audio" {
			return md
		}
	}
	return nil
}

func sdpAddrType(ip netip.Addr) string {
	if ip.Is6() {
		return "IP6"
	}
	return "IP4"
}
