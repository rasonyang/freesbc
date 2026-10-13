// Package hep encodes HEPv3 packets and sends them to a HOMER collector.
//
// It is a library with no policy: it knows nothing about SIP or RTCP, reads
// no configuration, and imports nothing from this module. The caller decides
// what to mirror and hands over finished payload bytes.
//
// Facts about HOMER 11 that shaped the design:
//
//   - It takes HEP on 9060 over UDP and TCP, and HEP over TLS on 9061 (mutual
//     TLS optional). It never replies, so the sender never reads a response.
//   - It does not check the auth key chunk (0x0e), so there is no password
//     support. Only the payload type (0x0b) and the payload (0x0f) are
//     required; a packet without 0x0b is dropped.
//   - It does not support the gzip payload chunk (0x10), so nothing is ever
//     compressed.
//   - A packet is at most 65507 bytes. Over TCP and TLS the framing is the
//     HEP length field alone: packets are written back to back.
//   - It never drops in user space. Overload becomes TCP backpressure or
//     kernel UDP drops, so the sender bounds itself and drops instead.
//
// Ownership: [Sender.Send] takes ownership of Packet.Payload. The caller must
// not modify the slice afterwards, because encoding happens later on the
// writer goroutine. The Packet struct itself is copied.
package hep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// MaxPacketSize is the largest HEP packet HOMER accepts (the UDP payload
// limit). A larger packet is refused by the encoder.
const MaxPacketSize = 65507

// PayloadType is the HEP payload type chunk (0x0b).
type PayloadType uint8

const (
	PayloadSIP      PayloadType = 1
	PayloadRTCPJSON PayloadType = 5
	PayloadLog      PayloadType = 100
)

// Generic chunk types (vendor 0x0000).
const (
	chunkFamily    = 0x01
	chunkProto     = 0x02
	chunkSrc4      = 0x03
	chunkDst4      = 0x04
	chunkSrc6      = 0x05
	chunkDst6      = 0x06
	chunkSrcPort   = 0x07
	chunkDstPort   = 0x08
	chunkTimeSec   = 0x09
	chunkTimeUsec  = 0x0a
	chunkPayType   = 0x0b
	chunkCaptureID = 0x0c
	chunkPayload   = 0x0f
	chunkCorrID    = 0x11
	chunkNodeName  = 0x13

	familyIPv4 = 2
	familyIPv6 = 10

	headerLen      = 6 // "HEP3" + uint16 total length
	chunkHeaderLen = 6 // vendor, type, length
)

// Errors returned by the encoder.
var (
	ErrTooLarge       = errors.New("hep: packet exceeds 65507 bytes")
	ErrFamilyMismatch = errors.New("hep: source and destination address families differ")
	ErrBadAddr        = errors.New("hep: invalid source or destination address")
	ErrBadType        = errors.New("hep: payload type is zero")
)

// Packet is one captured message. Src and Dst are the endpoints as seen on the
// wire; Proto is the IP protocol number (17 UDP, 6 TCP).
type Packet struct {
	Src, Dst      netip.AddrPort
	Proto         uint8
	Time          time.Time // zero means the time of encoding
	Type          PayloadType
	CorrelationID string // omitted when empty
	Payload       []byte
}

// AppendPacket appends the HEPv3 encoding of p to dst. captureID is the
// capture agent ID chunk (0x0c); node is the node name chunk (0x13), omitted
// when empty. A 4in6 address is encoded as IPv4. On error dst is returned
// unchanged.
func AppendPacket(dst []byte, p *Packet, captureID uint32, node string) ([]byte, error) {
	if !p.Src.IsValid() || !p.Dst.IsValid() {
		return dst, ErrBadAddr
	}
	if p.Type == 0 {
		return dst, ErrBadType
	}
	src, dstA := p.Src.Addr().Unmap(), p.Dst.Addr().Unmap()
	if src.Is4() != dstA.Is4() {
		return dst, ErrFamilyMismatch
	}
	v4 := src.Is4()
	addrLen := 16
	if v4 {
		addrLen = 4
	}

	// Compute the size first so an oversize packet costs no allocation.
	size := headerLen +
		(chunkHeaderLen + 1) + (chunkHeaderLen + 1) + // family, proto
		2*(chunkHeaderLen+addrLen) +
		2*(chunkHeaderLen+2) + // ports
		2*(chunkHeaderLen+4) + // time
		(chunkHeaderLen + 1) + // payload type
		(chunkHeaderLen + 4) + // capture ID
		chunkHeaderLen + len(p.Payload)
	if p.CorrelationID != "" {
		size += chunkHeaderLen + len(p.CorrelationID)
	}
	if node != "" {
		size += chunkHeaderLen + len(node)
	}
	// Each chunk length is a uint16 that includes its 6-byte header.
	if size > MaxPacketSize || chunkHeaderLen+len(p.Payload) > 0xffff ||
		chunkHeaderLen+len(p.CorrelationID) > 0xffff || chunkHeaderLen+len(node) > 0xffff {
		return dst, ErrTooLarge
	}

	t := p.Time
	if t.IsZero() {
		t = time.Now()
	}

	start := len(dst)
	dst = append(dst, 'H', 'E', 'P', '3', byte(size>>8), byte(size))
	fam := byte(familyIPv6)
	if v4 {
		fam = familyIPv4
	}
	dst = append(appendChunkHeader(dst, chunkFamily, 1), fam)
	dst = append(appendChunkHeader(dst, chunkProto, 1), p.Proto)
	if v4 {
		s, d := src.As4(), dstA.As4()
		dst = appendChunk(dst, chunkSrc4, s[:])
		dst = appendChunk(dst, chunkDst4, d[:])
	} else {
		s, d := src.As16(), dstA.As16()
		dst = appendChunk(dst, chunkSrc6, s[:])
		dst = appendChunk(dst, chunkDst6, d[:])
	}
	dst = binary.BigEndian.AppendUint16(appendChunkHeader(dst, chunkSrcPort, 2), p.Src.Port())
	dst = binary.BigEndian.AppendUint16(appendChunkHeader(dst, chunkDstPort, 2), p.Dst.Port())
	dst = binary.BigEndian.AppendUint32(appendChunkHeader(dst, chunkTimeSec, 4), uint32(t.Unix()))
	dst = binary.BigEndian.AppendUint32(appendChunkHeader(dst, chunkTimeUsec, 4), uint32(t.Nanosecond()/1000))
	dst = append(appendChunkHeader(dst, chunkPayType, 1), byte(p.Type))
	dst = binary.BigEndian.AppendUint32(appendChunkHeader(dst, chunkCaptureID, 4), captureID)
	dst = appendChunk(dst, chunkPayload, p.Payload)
	if p.CorrelationID != "" {
		dst = append(appendChunkHeader(dst, chunkCorrID, len(p.CorrelationID)), p.CorrelationID...)
	}
	if node != "" {
		dst = append(appendChunkHeader(dst, chunkNodeName, len(node)), node...)
	}
	if got := len(dst) - start; got != size {
		// A bug in the size arithmetic above; never emit a bad length.
		return dst[:start], fmt.Errorf("hep: internal size mismatch %d != %d", got, size)
	}
	return dst, nil
}

func appendChunk(dst []byte, typ uint16, data []byte) []byte {
	return append(appendChunkHeader(dst, typ, len(data)), data...)
}

// appendChunkHeader appends a generic chunk header for n bytes of data; the
// caller appends the data, so fixed-size chunks need no temporary slice.
func appendChunkHeader(dst []byte, typ uint16, n int) []byte {
	dst = binary.BigEndian.AppendUint16(dst, 0) // vendor: generic
	dst = binary.BigEndian.AppendUint16(dst, typ)
	return binary.BigEndian.AppendUint16(dst, uint16(chunkHeaderLen+n))
}
