package sip

import "github.com/emiago/sipgo/sip"

// MaxReadSize is the read-filter size cap a plane passes to ReadFilter.
//
// It must stay below sipgo's TransportBufferReadSize (32 KiB in v1.4.3):
// every sipgo transport reads into a buffer of that size, so no read the
// filter sees is ever longer, and a cap at or above it could never fire.
// An oversized UDP datagram arrives truncated to the buffer size and a
// longer WebSocket frame is cut the same way, so both now exceed the cap
// and are dropped before the parser sees a partial message. A stream
// transport's messages are bounded separately, by sipgo's
// ParseMaxMessageLength (64 KiB), because a stream read is a chunk and not
// a message.
//
// 24 KiB holds the largest SDP body the sdp package accepts (16 KiB) plus
// a generous 8 KiB of headers; real requests, even a WebRTC INVITE with a
// full candidate list, stay under 8 KiB.
const MaxReadSize = 24 << 10

// ReadFilter wraps a plane's accept policy in the two rules every sipgo
// transport read filter must obey.
//
// The first is the size cap: maxSize bounds a read BEFORE the parser sees
// it, so one oversized datagram or WebSocket frame is dropped rather than
// parsed. A maxSize of 0 disables the cap; a maxSize at or above sipgo's
// read buffer disables it too, in effect (see MaxReadSize).
//
// The second, and the reason this wrapper exists at all, is that the
// filter must NEVER return an error. sipgo treats a filter error as fatal
// to the whole read loop (transport_udp.go logs it and returns), so one
// hostile packet would kill a listener. A rejected read returns nil bytes
// and a nil error, which is how sipgo is told to discard it.
//
// accept is the plane's own trust decision — which sources this listener
// answers — and is evaluated only for reads that pass the cap. A nil
// accept lets everything through.
func ReadFilter(maxSize int, accept func(info sip.TransportReadProps) bool) sip.TransportReadFilter {
	return func(info sip.TransportReadProps, data []byte) ([]byte, error) {
		if maxSize > 0 && len(data) > maxSize {
			return nil, nil
		}
		if accept != nil && !accept(info) {
			return nil, nil
		}
		return data, nil
	}
}
