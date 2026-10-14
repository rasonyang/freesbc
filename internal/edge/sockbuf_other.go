//go:build !unix

package edge

import "net"

// socketBuffers cannot read the sizes back here; 0 means unknown.
func socketBuffers(*net.UDPConn) (rcv, snd int) { return 0, 0 }
