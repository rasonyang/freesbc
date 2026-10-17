package edge

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/hep"
)

// The HEP mirror ships a copy of every SIP message the edge receives or sends
// to a HOMER collector (issue #128). Inbound messages are copied by the
// transport read filter, outbound ones by sipgo's global SIP tracer. Neither
// ever blocks or fails the message: hep.Sender.Send only queues, and a full
// queue drops the copy.

// hepMirror is one server's mirror. It is nil on a server with no hep
// section, and every method is a no-op on nil.
type hepMirror struct {
	sender *hep.Sender
	redact bool
	// bind and pub are public.bind and public.ip. A local address equal to
	// bind is reported as pub, and a listener's port as its advertised one
	// (advPorts), so behind NAT the HOMER ladder shows the address the SIP
	// headers carry.
	bind, pub netip.Addr
	// advPorts maps a public listener's bound port to its edge.advertise
	// port, for the listeners where the two differ. tcp, tls, ws and wss
	// share one key space (protocol 6), where validation keeps their ports
	// distinct.
	advPorts map[hepPort]uint16
}

// hepPort is a local port under one HEP protocol (17 UDP, 6 TCP).
type hepPort struct {
	proto uint8
	port  uint16
}

// hepAdvPorts is the advPorts table of a config: every public listener whose
// advertised port differs from the one it binds. Nil when none does.
func hepAdvPorts(cfg *config.Config) map[hepPort]uint16 {
	var out map[hepPort]uint16
	for _, tr := range config.Transports {
		listen, adv := cfg.Edge.Listen.Port(tr), cfg.AdvertisedPort(tr)
		if listen == 0 || listen == adv {
			continue
		}
		if out == nil {
			out = map[hepPort]uint16{}
		}
		out[hepPort{hepProto(tr), uint16(listen)}] = uint16(adv)
	}
	return out
}

// WithHEP mirrors the edge's SIP signaling to sender. The server does not
// close the sender: its owner does, after the server has stopped. Whether
// Authorization headers are masked comes from the hep.redact_auth setting of
// the startup snapshot.
func WithHEP(sender *hep.Sender) Option {
	return func(o *options) { o.hep = sender }
}

// hepRoutes maps the local address of a socket to the mirror of the server
// that owns it. sipgo's tracer is process-wide and carries no server
// identity, so several servers in one process (tests) are told apart by the
// local address of the socket that wrote the message. Keys are
// netip.AddrPort with a 4in6 address unmapped.
var hepRoutes sync.Map

var hepTracerOnce sync.Once

// installHEPTracer turns on sipgo's SIP debug hook, once per process.
//
// sipgo v1.6.0 has no write hook. Its only outbound tap is the package-level
// SIPDebugTracer, which fires from the UDP, TCP and WS connection writes and
// only while sip.SIPDebug is true. Both globals are unsynchronised, so they
// are set here, from New, before any server of this process runs. SIPTraceRead
// is ignored: it fires before the read filter, so it would mirror what the
// shield is about to drop and would carry the unstamped bytes.
//
// SIPDebug also turns on a few extra Debug logs in sipgo's WS transport.
func installHEPTracer() {
	hepTracerOnce.Do(func() {
		sip.SIPDebugTracer(hepTracer{})
		sip.SIPDebug = true
	})
}

type hepTracer struct{}

func (hepTracer) SIPTraceRead(string, string, string, []byte) {}

// SIPTraceWrite sees every message sipgo writes, retransmissions, 100 Trying
// and stateless replies included. transport is UDP, TCP or WS: sipgo reports
// a TLS connection as TCP and a WSS one as WS, which is harmless, because the
// HEP protocol field is 17 or 6 and the local port tells the sockets apart.
func (hepTracer) SIPTraceWrite(transport, laddr, raddr string, msg []byte) {
	local, err := netip.ParseAddrPort(laddr)
	if err != nil {
		return
	}
	v, ok := hepRoutes.Load(netip.AddrPortFrom(local.Addr().Unmap(), local.Port()))
	if !ok {
		return
	}
	remote, err := netip.ParseAddrPort(raddr)
	if err != nil {
		return
	}
	v.(*hepMirror).capture(hepProto(transport), local, remote, false, msg)
}

// hepProto is the IP protocol number HEP carries: 17 for UDP, 6 for every
// stream transport.
func hepProto(transport string) uint8 {
	if strings.EqualFold(transport, "udp") {
		return 17
	}
	return 6
}

// route registers a local socket address as this mirror's; the returned
// function removes it again.
func (m *hepMirror) route(a netip.AddrPort) (unroute func()) {
	if m == nil {
		return func() {}
	}
	key := netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	hepRoutes.Store(key, m)
	return func() { hepRoutes.CompareAndDelete(key, m) }
}

// inbound mirrors a read the filter accepted. It runs before the arrival
// marker is stamped, so the per-process secret never reaches the collector,
// and it copies what it keeps: data is sipgo's read buffer.
func (m *hepMirror) inbound(info sip.TransportReadProps, data []byte, byteStream bool) {
	if m == nil {
		return
	}
	local, ok1 := addrPortOf(info.LocalAddr)
	remote, ok2 := addrPortOf(info.RemoteAddr)
	if !ok1 || !ok2 {
		return
	}
	proto := hepProto(info.Transport)
	if !byteStream {
		m.capture(proto, local, remote, true, data)
		return
	}
	// A tcp or tls read is a chunk of the stream: mirror each complete
	// message in it. A message split over reads is not mirrored.
	for {
		msg, rest := nextStreamMessage(data)
		if msg == nil {
			return
		}
		m.capture(proto, local, remote, true, msg)
		data = rest
	}
}

// capture queues one message. local is this process's end of the socket;
// inbound says the message was received on it. A message with no Call-ID is
// not mirrored: HOMER cannot correlate it, and a malformed flood that got
// past the filter should not become collector load.
func (m *hepMirror) capture(proto uint8, local, remote netip.AddrPort, inbound bool, data []byte) {
	if m == nil {
		return
	}
	callID := callIDOf(data)
	if callID == "" {
		return
	}
	if local.Addr().Unmap() == m.bind {
		port := local.Port()
		if adv, ok := m.advPorts[hepPort{proto, port}]; ok {
			port = adv
		}
		local = netip.AddrPortFrom(m.pub, port)
	}
	p := hep.Packet{Proto: proto, Type: hep.PayloadSIP, CorrelationID: callID}
	if inbound {
		p.Src, p.Dst = remote, local
	} else {
		p.Src, p.Dst = local, remote
	}
	if m.redact {
		p.Payload = redactAuthHeaders(data)
	} else {
		p.Payload = bytes.Clone(data)
	}
	m.sender.Send(&p)
}

// addrPortOf converts a socket address without allocating for the common
// concrete types.
func addrPortOf(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case nil:
		return netip.AddrPort{}, false
	case *net.UDPAddr:
		return v.AddrPort(), v.AddrPort().IsValid()
	case *net.TCPAddr:
		return v.AddrPort(), v.AddrPort().IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

// headerLines walks the header section of a SIP message: it calls fn with
// each line (without its terminator) and the offset of its first byte, and
// stops at the empty line or when fn returns false. The start line is
// passed too, as index 0. Leading CR/LF bytes before the start line are
// skipped, as the parser skips them. It returns the offset where the body
// starts (len(data) when there is no empty line).
func headerLines(data []byte, fn func(i int, off int, line []byte) bool) int {
	pos := 0
	for pos < len(data) && (data[pos] == '\r' || data[pos] == '\n') {
		pos++
	}
	for i := 0; pos < len(data); i++ {
		end := bytes.IndexByte(data[pos:], '\n')
		next := len(data)
		line := data[pos:]
		if end >= 0 {
			line = data[pos : pos+end]
			next = pos + end + 1
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			return next
		}
		if !fn(i, pos, line) {
			return next
		}
		pos = next
	}
	return len(data)
}

// headerName returns the trimmed header name of line, or nil when it has
// none (a continuation line, or no colon).
func headerName(line []byte) (name, value []byte) {
	if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
		return nil, nil
	}
	c := bytes.IndexByte(line, ':')
	if c < 0 {
		return nil, nil
	}
	return bytes.TrimSpace(line[:c]), bytes.TrimSpace(line[c+1:])
}

// callIDOf returns the Call-ID value (long or compact form) of a SIP
// message, or "" when there is none. It scans the header section only and
// allocates just the result.
func callIDOf(data []byte) string {
	var id string
	headerLines(data, func(i, _ int, line []byte) bool {
		if i == 0 {
			return true // start line
		}
		name, value := headerName(line)
		if len(name) == 1 && (name[0] == 'i' || name[0] == 'I') || strings.EqualFold(string(name), "call-id") {
			id = string(value)
			return false
		}
		return true
	})
	return id
}

// redactedValue replaces the value of a masked header.
const redactedValue = "REDACTED"

// redactAuthHeaders returns a copy of a SIP message with the value of every
// Authorization and Proxy-Authorization header replaced by redactedValue,
// folded continuation lines of those headers included. Neither header has a
// compact form. The body is copied untouched; data is never modified.
func redactAuthHeaders(data []byte) []byte {
	out := make([]byte, 0, len(data))
	last := 0        // data[:last] is already in out
	masking := false // the previous header line was a masked one
	headerLines(data, func(i, off int, line []byte) bool {
		if i == 0 {
			return true
		}
		if line[0] == ' ' || line[0] == '\t' {
			if masking { // fold of a masked header: drop it, keep its terminator
				last = off + len(line)
			}
			return true
		}
		masking = false
		name, _ := headerName(line)
		if strings.EqualFold(string(name), "authorization") || strings.EqualFold(string(name), "proxy-authorization") {
			masking = true
			c := bytes.IndexByte(line, ':')
			out = append(out, data[last:off+c+1]...)
			out = append(out, ' ')
			out = append(out, redactedValue...)
			last = off + len(line)
		}
		return true
	})
	return append(out, data[last:]...)
}

// nextStreamMessage splits the first complete message off a chunk of a
// stream, framing it by Content-Length. It returns nil when the chunk holds
// no complete message (empty, keep-alive only, or a partial message).
func nextStreamMessage(data []byte) (msg, rest []byte) {
	data = bytes.TrimLeft(data, "\r\n")
	if len(data) == 0 {
		return nil, nil
	}
	cl := 0
	headerLines(data, func(i, _ int, line []byte) bool {
		if i == 0 {
			return true
		}
		name, value := headerName(line)
		if len(name) == 1 && (name[0] == 'l' || name[0] == 'L') || strings.EqualFold(string(name), "content-length") {
			n := 0
			for _, b := range value {
				if b < '0' || b > '9' || n > 1<<20 {
					n = 0
					break
				}
				n = n*10 + int(b-'0')
			}
			cl = n
			return false
		}
		return true
	})
	var body int
	if hdrEnd := bytes.Index(data, []byte("\r\n\r\n")); hdrEnd >= 0 {
		body = hdrEnd + 4
	} else if hdrEnd := bytes.Index(data, []byte("\n\n")); hdrEnd >= 0 {
		body = hdrEnd + 2
	} else {
		return nil, nil
	}
	if body+cl > len(data) {
		return nil, nil
	}
	return data[:body+cl], data[body+cl:]
}
