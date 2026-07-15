package sig

import (
	"fmt"
	"net/netip"
	"strconv"

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

// rewriteSDP points the SDP at our media: session-level c= becomes ourIP,
// and each audio m= port becomes rtpPort (a=rtcp, if present, becomes
// rtpPort+1). It returns the re-marshalled SDP. Errors on unparseable input
// or SDP with no audio media.
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
	for _, md := range sd.MediaDescriptions {
		if md.MediaName.Media != "audio" {
			continue
		}
		md.MediaName.Port = sdp.RangedPort{Value: rtpPort}
		// Drop any media-level c= so the session-level one governs.
		md.ConnectionInformation = nil
		for i := range md.Attributes {
			if md.Attributes[i].Key == "rtcp" {
				md.Attributes[i].Value = strconv.Itoa(rtpPort + 1)
			}
		}
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
