package sip

import "github.com/emiago/sipgo/sip"

// ReadFilter wraps a plane's accept policy in the two rules every sipgo
// transport read filter must obey.
//
// The first is the size cap: maxSize bounds a message BEFORE the parser
// sees it, so one oversized datagram or WebSocket frame cannot decide how
// much memory a read costs. A maxSize of 0 disables the cap.
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
