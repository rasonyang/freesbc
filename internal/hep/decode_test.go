package hep

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// decoded is the test-only view of one HEPv3 packet.
type decoded struct {
	Packet
	CaptureID uint32
	Node      string
}

// decodePacket parses one packet from b and returns it and the bytes used.
// It is strict about lengths and never panics on arbitrary input.
func decodePacket(b []byte) (d decoded, n int, err error) {
	if len(b) < headerLen || string(b[:4]) != "HEP3" {
		return d, 0, errors.New("bad header")
	}
	total := int(binary.BigEndian.Uint16(b[4:6]))
	if total < headerLen || total > len(b) {
		return d, 0, errors.New("bad total length")
	}
	var fam byte
	var src, dst netip.Addr
	var sp, dp uint16
	var sec, usec uint32
	body := b[headerLen:total]
	for len(body) > 0 {
		if len(body) < chunkHeaderLen {
			return d, 0, errors.New("short chunk header")
		}
		vendor := binary.BigEndian.Uint16(body[0:2])
		typ := binary.BigEndian.Uint16(body[2:4])
		l := int(binary.BigEndian.Uint16(body[4:6]))
		if l < chunkHeaderLen || l > len(body) {
			return d, 0, errors.New("bad chunk length")
		}
		data := body[chunkHeaderLen:l]
		body = body[l:]
		if vendor != 0 {
			continue
		}
		switch typ {
		case chunkFamily:
			if len(data) == 1 {
				fam = data[0]
			}
		case chunkProto:
			if len(data) == 1 {
				d.Proto = data[0]
			}
		case chunkSrc4, chunkDst4:
			if len(data) != 4 {
				return d, 0, errors.New("bad v4 length")
			}
			a := netip.AddrFrom4([4]byte(data))
			if typ == chunkSrc4 {
				src = a
			} else {
				dst = a
			}
		case chunkSrc6, chunkDst6:
			if len(data) != 16 {
				return d, 0, errors.New("bad v6 length")
			}
			a := netip.AddrFrom16([16]byte(data))
			if typ == chunkSrc6 {
				src = a
			} else {
				dst = a
			}
		case chunkSrcPort, chunkDstPort:
			if len(data) != 2 {
				return d, 0, errors.New("bad port length")
			}
			if typ == chunkSrcPort {
				sp = binary.BigEndian.Uint16(data)
			} else {
				dp = binary.BigEndian.Uint16(data)
			}
		case chunkTimeSec, chunkTimeUsec, chunkCaptureID:
			if len(data) != 4 {
				return d, 0, errors.New("bad uint32 length")
			}
			v := binary.BigEndian.Uint32(data)
			switch typ {
			case chunkTimeSec:
				sec = v
			case chunkTimeUsec:
				usec = v
			default:
				d.CaptureID = v
			}
		case chunkPayType:
			if len(data) == 1 {
				d.Type = PayloadType(data[0])
			}
		case chunkPayload:
			d.Payload = append([]byte{}, data...)
		case chunkCorrID:
			d.CorrelationID = string(data)
		case chunkNodeName:
			d.Node = string(data)
		}
	}
	if (fam == familyIPv4) != src.Is4() && src.IsValid() {
		return d, 0, errors.New("family does not match address")
	}
	d.Src = netip.AddrPortFrom(src, sp)
	d.Dst = netip.AddrPortFrom(dst, dp)
	d.Time = time.Unix(int64(sec), int64(usec)*1000).UTC()
	return d, total, nil
}
