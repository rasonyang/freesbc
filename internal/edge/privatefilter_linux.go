//go:build linux

package edge

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Linux's weak host model delivers a datagram for any local address on any
// interface, so a datagram addressed to private.ip and sent into the public
// NIC reaches the private socket, where a spoofed switch source is believed
// (issue #90). SO_BINDTODEVICE would fix that too, but it pins the send path
// to the private interface as well: a switch node that is not reachable
// there would then look like a silent one and hide the transport error the
// passive failover relies on. The private socket therefore carries a classic
// BPF receive filter on the ingress device instead: only datagrams that
// arrived on the interface owning private.ip (or were delivered locally, for
// a co-located switch) are queued, and the send path is untouched.
//
// The filter reads skb->dev->ifindex: the kernel's SKF_AD_IFINDEX loads the
// device, not the original skb->skb_iif (see convert_skb_access in
// net/core/filter.c). VLAN, bond and bridge are fine, because by the time
// the socket filter runs the device is the upper one that owns the address.
// A VRF is not: l3mdev rewrites skb->dev to the VRF master while the
// address lives on the slave, so switch traffic over a VRF is dropped.
// Switch traffic must arrive on the interface that owns private.ip, or on
// loopback; docs/edge.md states the requirement and the known limitations.

// privateSocketFilter is a variable so the wiring test can observe that
// openListener asks for the filter on udp-private and nowhere else; see the
// same seam on media.listenUDP. It returns a net.ListenConfig.Control that
// installs the ingress filter on the private socket, with ifname the
// interface that owns private.ip.
var privateSocketFilter = func(ifname string) (func(network, address string, c syscall.RawConn) error, error) {
	priv, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	loop, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	prog, err := ifindexFilter(priv.Index, loop.Index)
	if err != nil {
		return nil, err
	}
	return attachFilter(prog), nil
}

// attachFilter installs prog on the socket the Control callback is given,
// before it is bound, so no unfiltered datagram can be queued.
func attachFilter(prog []unix.SockFilter) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
			serr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)
			if serr != nil {
				// net wraps this in a listen error that names only the
				// socket; say that the filter was what failed.
				serr = fmt.Errorf("attach private ingress filter: %w", serr)
			}
		}); err != nil {
			return err
		}
		return serr
	}
}

// ifindexFilter is the BPF program: load the ingress device index and
// accept when it equals one of ifindexes; every other datagram is dropped
// before it can be queued to the socket.
func ifindexFilter(ifindexes ...int) ([]unix.SockFilter, error) {
	// 0:              ld  skb->dev->ifindex
	// 1..n:           jeq ifindexes[i] -> accept, else the next test
	// n+1:            ret ACCEPT
	// n+2:            ret 0
	insns := make([]bpf.Instruction, 0, len(ifindexes)+3)
	insns = append(insns, bpf.LoadExtension{Num: bpf.ExtInterfaceIndex})
	for i, idx := range ifindexes {
		// A match skips to the accept; a miss falls through to the next
		// test, and the last test's miss skips the accept to the drop.
		jf := uint8(0)
		if i == len(ifindexes)-1 {
			jf = 1
		}
		insns = append(insns, bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       uint32(idx),
			SkipTrue:  uint8(len(ifindexes) - i - 1),
			SkipFalse: jf,
		})
	}
	insns = append(insns, bpf.RetConstant{Val: 0xFFFFFFFF}, bpf.RetConstant{Val: 0})
	raw, err := bpf.Assemble(insns)
	if err != nil {
		return nil, err
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return prog, nil
}
