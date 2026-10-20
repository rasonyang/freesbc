package edge

import (
	"log/slog"
	"net"
)

// Kernel buffer sizes requested for every UDP SIP socket (public and
// private). The OS default (212992 bytes on Linux) overflows under a burst
// or a GC pause and the kernel drops datagrams silently (UdpRcvbufErrors,
// issue #171). The receive request is 8 MiB (4 MiB until issue #235): a GC
// mark phase can keep a socket's single read loop off the CPU long enough for
// carrier-in traffic above ~3500 CPS to fill 4 MiB. Fixed constants, not
// config: the request is capped by net.core.rmem_max / wmem_max (Linux) or
// kern.ipc.maxsockbuf (macOS), which is the operator's knob; Linux grants
// double the (capped) request for its bookkeeping. RTP sockets are left
// alone: each carries one ~50 pps stream.
const (
	udpSIPReadBuffer  = 8 << 20
	udpSIPWriteBuffer = 1 << 20
)

// sizeUDPSocket asks for udpSIPReadBuffer and udpSIPWriteBuffer on pc and
// logs what the kernel granted. It never fails: a socket with a small
// buffer still works, so a refusal or a cap is a WARN only.
func sizeUDPSocket(log *slog.Logger, pc net.PacketConn) {
	rcv, snd, capped := applyUDPBuffers(pc, udpSIPReadBuffer, udpSIPWriteBuffer, log)
	if !capped {
		log.Debug("udp socket buffers", "addr", pc.LocalAddr().String(), "rcvbuf", rcv, "sndbuf", snd)
	}
}

// applyUDPBuffers requests the sizes, reads back the granted ones and warns
// for each that came back smaller than asked. A read-back of 0 means it
// could not be read and is not treated as a cap.
func applyUDPBuffers(pc net.PacketConn, wantRcv, wantSnd int, log *slog.Logger) (rcv, snd int, capped bool) {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return 0, 0, false
	}
	addr := uc.LocalAddr().String()
	if err := uc.SetReadBuffer(wantRcv); err != nil {
		log.Warn("udp socket: set receive buffer failed", "addr", addr, "requested", wantRcv, "error", err)
		capped = true
	}
	if err := uc.SetWriteBuffer(wantSnd); err != nil {
		log.Warn("udp socket: set send buffer failed", "addr", addr, "requested", wantSnd, "error", err)
		capped = true
	}
	rcv, snd = socketBuffers(uc)
	if rcv > 0 && rcv < wantRcv {
		log.Warn("udp socket receive buffer below request; datagrams may drop under bursts: raise net.core.rmem_max (Linux) or kern.ipc.maxsockbuf (macOS)",
			"addr", addr, "requested", wantRcv, "effective", rcv)
		capped = true
	}
	if snd > 0 && snd < wantSnd {
		log.Warn("udp socket send buffer below request: raise net.core.wmem_max (Linux) or kern.ipc.maxsockbuf (macOS)",
			"addr", addr, "requested", wantSnd, "effective", snd)
		capped = true
	}
	return rcv, snd, capped
}
