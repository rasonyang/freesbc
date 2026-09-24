package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// audit: P3-MED-FUZZ
//
// Fuzz targets for the media receive paths that parse untrusted bytes:
// the RFC 7983 first-byte classifier and RFC 5761 RTP/RTCP split, the
// WebRTC demultiplexer, SRTP/SRTCP unprotect, the ICE-Lite socket before
// establishment (STUN parsing inside pion's UDP mux), and an established
// browser leg (demux → DTLS / SRTP relay). A crash in any is a P0.

func auditSeedPackets(f *testing.F) {
	stun := make([]byte, 20)
	binary.BigEndian.PutUint16(stun[0:], 0x0001) // Binding request
	binary.BigEndian.PutUint32(stun[4:], 0x2112A442)
	copy(stun[8:], "abcdefghijkl")
	stunUser := append(append([]byte(nil), stun...), 0x00, 0x06, 0x00, 0x09, 'x', 'x', 'x', 'x', ':', 'y', 'y', 'y', 'y', 0, 0, 0)
	binary.BigEndian.PutUint16(stunUser[2:], uint16(len(stunUser)-20))
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(stun)
	f.Add(stunUser)
	f.Add([]byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1})    // DTLS record header
	f.Add([]byte{21, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 2, 1}) // DTLS alert, epoch 1
	f.Add(rtpPacket(0, 1, 160))
	f.Add([]byte{0x80, 200, 0, 6, 0xde, 0xad, 0xbe, 0xef})                       // RTCP SR header
	f.Add([]byte{0x90, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0xbe, 0xde, 0xff, 0xff}) // RTP ext, huge length
	f.Add([]byte{0xbf, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})                         // CC=15, truncated
	f.Add(bytes.Repeat([]byte{0xa0}, 1600))
}

func FuzzAuditClassify(f *testing.F) {
	auditSeedPackets(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		k := classify(b)
		if len(b) == 0 && k != muxUnknown {
			t.Fatalf("empty packet classified as %v", k)
		}
		if len(b) > 0 {
			c := b[0]
			want := muxUnknown
			if c >= 20 && c <= 63 {
				want = muxDTLS
			} else if c >= 128 && c <= 191 {
				want = muxSRTP
			}
			if k != want {
				t.Fatalf("classify(first=%d) = %v, want %v (RFC 7983)", c, k, want)
			}
		}
		_ = isRTCP(b)
	})
}

// auditPktConn is a datagram-preserving net.Conn fed from a channel, so
// the demultiplexer can be driven without sockets.
type auditPktConn struct {
	in     chan []byte
	once   sync.Once
	closed chan struct{}
}

func newAuditPktConn() *auditPktConn {
	return &auditPktConn{in: make(chan []byte, 64), closed: make(chan struct{})}
}

func (c *auditPktConn) Read(p []byte) (int, error) {
	select {
	case b := <-c.in:
		return copy(p, b), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}
func (c *auditPktConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *auditPktConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *auditPktConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *auditPktConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *auditPktConn) SetDeadline(time.Time) error      { return nil }
func (c *auditPktConn) SetReadDeadline(time.Time) error  { return nil }
func (c *auditPktConn) SetWriteDeadline(time.Time) error { return nil }

// FuzzAuditDemux splits the input into datagrams (1-byte length prefix,
// scaled ×8) and checks that every datagram lands on exactly the endpoint
// its first byte names, truncated to maxPacketSize, and nothing else.
func FuzzAuditDemux(f *testing.F) {
	auditSeedPackets(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		var dgrams [][]byte
		for len(b) > 0 && len(dgrams) < 32 {
			n := int(b[0]) * 8
			b = b[1:]
			if n > len(b) {
				n = len(b)
			}
			dgrams = append(dgrams, b[:n])
			b = b[n:]
		}
		conn := newAuditPktConn()
		d := newDemux(conn)
		defer d.Close()
		var wantDTLS, wantSRTP [][]byte
		for _, g := range dgrams {
			trunc := g
			if len(trunc) > maxPacketSize {
				trunc = trunc[:maxPacketSize]
			}
			switch classify(trunc) {
			case muxDTLS:
				wantDTLS = append(wantDTLS, trunc)
			case muxSRTP:
				wantSRTP = append(wantSRTP, trunc)
			}
			conn.in <- g
		}
		read := func(ep *muxEndpoint, want [][]byte, name string) {
			buf := make([]byte, 4096)
			for i, w := range want {
				_ = ep.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := ep.Read(buf)
				if err != nil {
					t.Fatalf("%s endpoint: datagram %d not delivered: %v", name, i, err)
				}
				if !bytes.Equal(buf[:n], w) {
					t.Fatalf("%s endpoint: datagram %d = %x, want %x", name, i, buf[:n], w)
				}
			}
			_ = ep.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if n, err := ep.Read(buf); err == nil {
				t.Fatalf("%s endpoint: unexpected extra datagram %x", name, buf[:n])
			}
		}
		read(d.dtls, wantDTLS, "dtls")
		read(d.srtp, wantSRTP, "srtp")
	})
}

// FuzzAuditSRTPUnprotect feeds arbitrary bytes to every SRTP/SRTCP
// transform the relay applies to inbound packets, for both suites.
func FuzzAuditSRTPUnprotect(f *testing.F) {
	auditSeedPackets(f)
	key := bytes.Repeat([]byte{0x5a}, SDESKeyLen)
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, suite := range []CryptoSuite{SuiteAES128CM80, SuiteAES128CM32} {
			c, err := NewSRTPContext(suite, key)
			if err != nil {
				t.Fatal(err)
			}
			in := append([]byte(nil), b...)
			_, _ = c.unprotectRTP(in)
			_, _ = c.unprotectRTCP(in)
			_, _ = c.protectRTP(in)
			_, _ = c.protectRTCP(in)
			if !bytes.Equal(in, b) {
				t.Fatalf("transform mutated its input buffer")
			}
		}
	})
}

// FuzzAuditSRTPRoundTrip checks that whatever plaintext RTP the relay
// manages to protect (RTP→SRTP interworking) decrypts back to the same
// bytes under the same key. See P3-MED-001.
func FuzzAuditSRTPRoundTrip(f *testing.F) {
	auditSeedPackets(f)
	key := bytes.Repeat([]byte{0x5a}, SDESKeyLen)
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, suite := range []CryptoSuite{SuiteAES128CM80, SuiteAES128CM32} {
			c, _ := NewSRTPContext(suite, key)
			r, _ := NewSRTPContext(suite, key)
			if p, ok := c.protectRTP(append([]byte(nil), b...)); ok {
				if got, ok := r.unprotectRTP(p); !ok || !bytes.Equal(got, b) {
					t.Fatalf("SRTP round trip failed (P3-MED-001): ok=%v", ok)
				}
			}
		}
	})
}

// FuzzAuditWebRTCLegPreICE sends each input as one UDP datagram to a
// WebRTC leg that is waiting for ICE: pion's UDP mux parses it as STUN
// from an unknown remote. The leg must neither crash nor fail.
func FuzzAuditWebRTCLegPreICE(f *testing.F) {
	auditSeedPackets(f)
	pool := newAuditPool("public", 47400, 47499, "127.0.0.1")
	id, err := ProcessDTLSIdentity()
	if err != nil {
		f.Fatal(err)
	}
	leg, err := NewWebRTCLeg(pool.PlanePool, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
		RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = leg.Close() })
	leg.Start(context.Background(), time.Hour)
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: leg.Port()})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = c.Close() })
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1500 {
			b = b[:1500]
		}
		_, _ = c.Write(b)
		select {
		case <-leg.Ready():
			t.Fatalf("leg left the establishing state after a hostile datagram: %v", leg.loadErr())
		default:
		}
	})
}

// FuzzAuditWebRTCEstablished writes each input over an established ICE
// connection into a live browser leg, where it reaches the demultiplexer
// and then either the DTLS connection or the SRTP relay. A single hostile
// datagram must not end the call.
func FuzzAuditWebRTCEstablished(f *testing.F) {
	auditSeedPackets(f)
	c := auditEstablishBrowserCall(f, 47500, 47599, 47600, 47699)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1500 {
			b = b[:1500]
		}
		// pion's ice.Conn refuses to send STUN-looking payloads; such
		// inputs never reach the leg and are skipped.
		if _, err := c.browserConn.Write(b); err != nil {
			if errors.Is(err, net.ErrClosed) {
				t.Fatalf("browser ICE connection closed: %v", err)
			}
			return
		}
		select {
		case <-c.sess.Done():
			t.Fatalf("browser media session ended after a hostile datagram %x", b)
		default:
		}
	})
}
