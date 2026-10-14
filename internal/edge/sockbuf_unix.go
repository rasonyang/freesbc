//go:build unix

package edge

import (
	"net"
	"runtime"
	"syscall"
)

// socketBuffers reads back the granted SO_RCVBUF and SO_SNDBUF, or 0 for one
// it cannot read. Linux reports double the granted size (the extra half is
// room for its bookkeeping), so the value is halved there.
func socketBuffers(uc *net.UDPConn) (rcv, snd int) {
	rc, err := uc.SyscallConn()
	if err != nil {
		return 0, 0
	}
	_ = rc.Control(func(fd uintptr) {
		if v, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
			rcv = v
		}
		if v, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF); err == nil {
			snd = v
		}
	})
	if runtime.GOOS == "linux" {
		rcv, snd = rcv/2, snd/2
	}
	return rcv, snd
}
