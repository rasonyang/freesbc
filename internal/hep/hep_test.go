package hep

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestAppendPacketGoldenIPv4(t *testing.T) {
	p := &Packet{
		Src:           netip.MustParseAddrPort("192.0.2.1:5060"),
		Dst:           netip.MustParseAddrPort("198.51.100.2:5061"),
		Proto:         17,
		Time:          time.Unix(1700000000, 123456000),
		Type:          PayloadSIP,
		CorrelationID: "cid",
		Payload:       []byte("INVITE"),
	}
	got, err := AppendPacket(nil, p, 0x01020304, "n1")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		'H', 'E', 'P', '3', 0x00, 0x7a,
		0, 0, 0x00, 0x01, 0, 7, 2, // family
		0, 0, 0x00, 0x02, 0, 7, 17, // proto
		0, 0, 0x00, 0x03, 0, 10, 192, 0, 2, 1, // src
		0, 0, 0x00, 0x04, 0, 10, 198, 51, 100, 2, // dst
		0, 0, 0x00, 0x07, 0, 8, 0x13, 0xc4, // sport 5060
		0, 0, 0x00, 0x08, 0, 8, 0x13, 0xc5, // dport 5061
		0, 0, 0x00, 0x09, 0, 10, 0x65, 0x53, 0xf1, 0x00, // sec
		0, 0, 0x00, 0x0a, 0, 10, 0x00, 0x01, 0xe2, 0x40, // usec 123456
		0, 0, 0x00, 0x0b, 0, 7, 1, // type
		0, 0, 0x00, 0x0c, 0, 10, 1, 2, 3, 4, // capture ID
		0, 0, 0x00, 0x0f, 0, 12, 'I', 'N', 'V', 'I', 'T', 'E',
		0, 0, 0x00, 0x11, 0, 9, 'c', 'i', 'd',
		0, 0, 0x00, 0x13, 0, 8, 'n', '1',
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got  % x\nwant % x", got, want)
	}
}

func TestAppendPacketGoldenIPv6(t *testing.T) {
	p := &Packet{
		Src:     netip.MustParseAddrPort("[2001:db8::1]:1000"),
		Dst:     netip.MustParseAddrPort("[2001:db8::2]:2000"),
		Proto:   6,
		Time:    time.Unix(1, 2000),
		Type:    PayloadLog,
		Payload: []byte{0xff},
	}
	got, err := AppendPacket(nil, p, 7, "")
	if err != nil {
		t.Fatal(err)
	}
	a1 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	a2 := append([]byte{}, a1...)
	a2[15] = 2
	var want []byte
	want = append(want, 'H', 'E', 'P', '3', 0, 0)
	want = append(want, 0, 0, 0, 1, 0, 7, 10)
	want = append(want, 0, 0, 0, 2, 0, 7, 6)
	want = append(want, 0, 0, 0, 5, 0, 22)
	want = append(want, a1...)
	want = append(want, 0, 0, 0, 6, 0, 22)
	want = append(want, a2...)
	want = append(want, 0, 0, 0, 7, 0, 8, 0x03, 0xe8)
	want = append(want, 0, 0, 0, 8, 0, 8, 0x07, 0xd0)
	want = append(want, 0, 0, 0, 9, 0, 10, 0, 0, 0, 1)
	want = append(want, 0, 0, 0, 0xa, 0, 10, 0, 0, 0, 2)
	want = append(want, 0, 0, 0, 0xb, 0, 7, 100)
	want = append(want, 0, 0, 0, 0xc, 0, 10, 0, 0, 0, 7)
	want = append(want, 0, 0, 0, 0xf, 0, 7, 0xff)
	want[4], want[5] = byte(len(want)>>8), byte(len(want))
	if !bytes.Equal(got, want) {
		t.Errorf("got  % x\nwant % x", got, want)
	}
}

func TestAppendPacketUnmaps4in6(t *testing.T) {
	p := &Packet{
		Src:  netip.MustParseAddrPort("[::ffff:192.0.2.1]:1"),
		Dst:  netip.MustParseAddrPort("198.51.100.2:2"),
		Type: PayloadSIP,
	}
	b, err := AppendPacket(nil, p, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := decodePacket(b)
	if err != nil || !d.Src.Addr().Is4() || d.Src.Addr().String() != "192.0.2.1" {
		t.Fatalf("src = %v, err %v", d.Src, err)
	}
}

func TestAppendPacketErrors(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.1:1")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:1")
	pre := []byte("keep")
	cases := map[string]struct {
		p    Packet
		want error
	}{
		"mixed families": {Packet{Src: v4, Dst: v6, Type: 1}, ErrFamilyMismatch},
		"invalid addr":   {Packet{Dst: v4, Type: 1}, ErrBadAddr},
		"no type":        {Packet{Src: v4, Dst: v4}, ErrBadType},
		"oversize": {Packet{Src: v4, Dst: v4, Type: 1,
			Payload: make([]byte, MaxPacketSize)}, ErrTooLarge},
	}
	for name, c := range cases {
		out, err := AppendPacket(pre, &c.p, 0, "")
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
		if string(out) != "keep" {
			t.Errorf("%s: dst modified", name)
		}
	}
}

func TestAppendPacketMaxFits(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.1:1")
	empty, err := AppendPacket(nil, &Packet{Src: v4, Dst: v4, Type: 1, Time: time.Unix(1, 0)}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	room := MaxPacketSize - len(empty)
	b, err := AppendPacket(nil, &Packet{Src: v4, Dst: v4, Type: 1, Time: time.Unix(1, 0),
		Payload: make([]byte, room)}, 0, "")
	if err != nil || len(b) != MaxPacketSize {
		t.Fatalf("len %d err %v", len(b), err)
	}
	if _, _, err := decodePacket(b); err != nil {
		t.Fatal(err)
	}
	_, err = AppendPacket(nil, &Packet{Src: v4, Dst: v4, Type: 1, Payload: make([]byte, room+1)}, 0, "")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func FuzzEncodeDecode(f *testing.F) {
	f.Add([]byte{192, 0, 2, 1}, []byte{198, 51, 100, 2}, uint16(5060), uint16(5061),
		uint8(17), int64(1700000000), uint32(123456), uint8(1), uint32(9), "cid", "node", []byte("INVITE"), false)
	f.Add(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), uint16(1), uint16(2),
		uint8(6), int64(0), uint32(0), uint8(100), uint32(0), "", "", []byte{}, true)
	f.Add([]byte("HEP3\x00\x06"), []byte{}, uint16(0), uint16(0), uint8(0), int64(0), uint32(0), uint8(0), uint32(0), "", "", []byte{}, false)
	f.Fuzz(func(t *testing.T, a, b []byte, sp, dp uint16, proto uint8, sec int64, usec uint32,
		typ uint8, cap32 uint32, corr, node string, payload []byte, v6 bool) {
		// Raw bytes into the decoder must not panic.
		decodePacket(a)
		decodePacket(payload)

		var src, dst netip.Addr
		if v6 {
			var x, y [16]byte
			copy(x[:], a)
			copy(y[:], b)
			src, dst = netip.AddrFrom16(x), netip.AddrFrom16(y)
		} else {
			var x, y [4]byte
			copy(x[:], a)
			copy(y[:], b)
			src, dst = netip.AddrFrom4(x), netip.AddrFrom4(y)
		}
		sec = int64(uint32(sec)) // the wire holds uint32 seconds
		p := Packet{
			Src: netip.AddrPortFrom(src, sp), Dst: netip.AddrPortFrom(dst, dp),
			Proto: proto, Time: time.Unix(sec, int64(usec%1000000)*1000),
			Type: PayloadType(typ), CorrelationID: corr, Payload: payload,
		}
		enc, err := AppendPacket(nil, &p, cap32, node)
		if err != nil {
			return // zero type, oversize or an unmappable family
		}
		d, n, err := decodePacket(enc)
		if err != nil || n != len(enc) {
			t.Fatalf("decode: n=%d len=%d err=%v", n, len(enc), err)
		}
		if d.Src != netip.AddrPortFrom(src.Unmap(), sp) || d.Dst != netip.AddrPortFrom(dst.Unmap(), dp) ||
			d.Proto != proto || d.Type != PayloadType(typ) || d.CaptureID != cap32 ||
			d.CorrelationID != corr || d.Node != node || !bytes.Equal(d.Payload, payload) ||
			!d.Time.Equal(p.Time) {
			t.Fatalf("round trip mismatch: %+v vs %+v", d, p)
		}
	})
}
