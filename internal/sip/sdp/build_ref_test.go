package sdp

import (
	"fmt"
	"strconv"
	"strings"

	pionsdp "github.com/pion/sdp/v3"
)

// This file keeps the pion-based body construction Build used before
// issue #173, verbatim, as the reference the append-based writer in
// build.go must match byte for byte (TestBuildMatchesPionReference and the
// Build fuzz targets). Change both together or not at all.

func (b Build) marshalDecliningPion(offer *Session) ([]byte, error) {
	if offer == nil {
		return b.marshalPion(nil)
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
		return b.marshalPion(nil)
	}
	return b.marshalPion(offer)
}

func (b Build) marshalPion(offer *Session) ([]byte, error) {
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
			Protos: b.protosPion(),
		},
	}
	for _, c := range b.Codecs {
		md.MediaName.Formats = append(md.MediaName.Formats, strconv.Itoa(int(c.PayloadType)))
	}

	if b.DTLS {
		md.Attributes = append(md.Attributes,
			attrPion("ice-lite", ""),
			attrPion("ice-ufrag", b.ICEUfrag),
			attrPion("ice-pwd", b.ICEPwd),
			attrPion("candidate", fmt.Sprintf("1 1 UDP %d %s %d typ host", iceLitePriority, b.Address.String(), b.Port)),
			attrPion("end-of-candidates", ""),
			attrPion("fingerprint", b.Fingerprint.String()),
			attrPion("setup", b.Setup),
		)
	}
	for _, c := range b.Codecs {
		md.Attributes = append(md.Attributes, attrPion("rtpmap", rtpmapValuePion(c)))
		if f := canonicalFMTPRef(c.Name, c.FMTP); f != "" {
			md.Attributes = append(md.Attributes, attrPion("fmtp", fmt.Sprintf("%d %s", c.PayloadType, f)))
		}
	}
	for _, c := range b.Crypto {
		md.Attributes = append(md.Attributes, attrPion("crypto", c.Value()))
	}
	dir := b.Direction
	if dir == "" {
		dir = SendRecv
	}
	md.Attributes = append(md.Attributes, attrPion(string(dir), ""))
	if b.RTCPMux {
		md.Attributes = append(md.Attributes, attrPion("rtcp-mux", ""))
	}
	if offer == nil {
		sd.MediaDescriptions = append(sd.MediaDescriptions, md)
		return sd.Marshal()
	}
	for i, sec := range offer.Sections {
		if i == offer.AudioIndex {
			sd.MediaDescriptions = append(sd.MediaDescriptions, md)
		} else {
			sd.MediaDescriptions = append(sd.MediaDescriptions, declinedSectionPion(sec))
		}
	}
	return sd.Marshal()
}

func (b Build) protosPion() []string {
	if b.DTLS {
		return []string{"UDP", "TLS", "RTP", "SAVPF"}
	}
	if len(b.Crypto) > 0 {
		return []string{"RTP", "SAVP"}
	}
	return []string{"RTP", "AVP"}
}

func rtpmapValuePion(c Codec) string {
	if c.Channels > 1 {
		return fmt.Sprintf("%d %s/%d/%d", c.PayloadType, c.Name, c.ClockRate, c.Channels)
	}
	return fmt.Sprintf("%d %s/%d", c.PayloadType, c.Name, c.ClockRate)
}

func attrPion(k, v string) pionsdp.Attribute { return pionsdp.Attribute{Key: k, Value: v} }

func declinedSectionPion(sec Section) *pionsdp.MediaDescription {
	return &pionsdp.MediaDescription{
		MediaName: pionsdp.MediaName{
			Media:   sec.Media,
			Port:    pionsdp.RangedPort{Value: 0},
			Protos:  sec.Proto,
			Formats: []string{placeholderFormatPion(sec.Proto)},
		},
	}
}

func placeholderFormatPion(proto []string) string {
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
