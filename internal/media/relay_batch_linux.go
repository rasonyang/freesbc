package media

import (
	"encoding/binary"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Batched RTP relay for Linux (issue #172): recvmmsg drains whatever is
// queued on the read socket, up to relayBatchSize datagrams, in one
// syscall, and the packets that survive the latch go out in one sendmmsg
// on the write socket (a lone packet with WriteToUDP). A socket carries
// one ~50 pps stream, so a batch is one packet unless the relay fell
// behind and packets queued; the gain, if any, appears only under load.
// See docs/notes/172-rtp-batch-io.md.
//
// The I/O runs through each socket's syscall.RawConn, so Go's netpoller
// still parks the goroutine while nothing is queued and Close still
// unblocks it, exactly as ReadFromUDP does. The headers, iovecs and
// sockaddrs are preallocated per loop: no allocation per packet.

const batchRelayAvailable = true

// relayBatchSize is the most datagrams one recvmmsg or sendmmsg moves.
// Each slot holds a relayBufSize buffer, so it costs about 12 KiB per RTP
// loop (two loops per session).
const relayBatchSize = 8

// mmsgSocket is one socket's recvmmsg or sendmmsg state. It is owned by
// one relay goroutine and is not safe for concurrent use.
type mmsgSocket struct {
	rc    syscall.RawConn
	inet6 bool // the socket is AF_INET6
	hdrs  [relayBatchSize]unix.Mmsghdr
	iovs  [relayBatchSize]unix.Iovec
	names [relayBatchSize]unix.RawSockaddrInet6 // large enough for either family

	// start and count are the headers the next call uses; n and errno
	// are its result. readFn and writeFn are bound once so a call does not
	// allocate a closure.
	start   int
	count   int
	n       int
	errno   syscall.Errno
	readFn  func(fd uintptr) bool
	writeFn func(fd uintptr) bool
}

func newMmsgSocket(c *net.UDPConn) (*mmsgSocket, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	m := &mmsgSocket{rc: rc}
	var family int
	var serr error
	if err := rc.Control(func(fd uintptr) {
		var sa unix.Sockaddr
		sa, serr = unix.Getsockname(int(fd))
		if _, ok := sa.(*unix.SockaddrInet6); ok {
			family = unix.AF_INET6
		}
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	m.inet6 = family == unix.AF_INET6
	for i := range m.hdrs {
		m.hdrs[i].Hdr.Iov = &m.iovs[i]
		m.hdrs[i].Hdr.SetIovlen(1)
	}
	m.readFn = m.recvmmsg
	m.writeFn = m.sendmmsg
	return m, nil
}

func (m *mmsgSocket) recvmmsg(fd uintptr) bool {
	for {
		n, _, e := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&m.hdrs[0])), uintptr(m.count), unix.MSG_DONTWAIT, 0, 0)
		if e == unix.EINTR {
			continue
		}
		if e == unix.EAGAIN {
			return false // nothing queued: park in the netpoller
		}
		m.n, m.errno = int(n), e
		return true
	}
}

func (m *mmsgSocket) sendmmsg(fd uintptr) bool {
	for {
		n, _, e := unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&m.hdrs[m.start])), uintptr(m.count), unix.MSG_DONTWAIT, 0, 0)
		if e == unix.EINTR {
			continue
		}
		if e == unix.EAGAIN {
			return false // send buffer full: wait for room, as WriteToUDP does
		}
		m.n, m.errno = int(n), e
		return true
	}
}

// bindBufs points the receive headers at bufs, once per loop: the
// buffers, iovecs and sockaddr slots never move, so a read only has to
// reset what the kernel wrote.
func (m *mmsgSocket) bindBufs(bufs *[relayBatchSize][]byte) {
	for i := range m.hdrs {
		b := bufs[i]
		m.iovs[i].Base = &b[0]
		m.iovs[i].SetLen(len(b))
		m.hdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&m.names[i]))
		m.hdrs[i].Hdr.Namelen = unix.SizeofSockaddrInet6
	}
}

// readBatch receives up to relayBatchSize datagrams into the buffers
// bindBufs installed, blocking until at least one is queued. It returns
// how many arrived; lenOf and srcOf read each one's length and source. An
// error means the socket is closed or broken, as for ReadFromUDP.
func (m *mmsgSocket) readBatch() (int, error) {
	for i := 0; i < m.n; i++ {
		m.hdrs[i].Hdr.Namelen = unix.SizeofSockaddrInet6 // the kernel shortened it
	}
	m.start, m.count, m.n = 0, len(m.hdrs), 0
	if err := m.rc.Read(m.readFn); err != nil {
		return 0, err
	}
	if m.errno != 0 {
		return 0, m.errno
	}
	return m.n, nil
}

// lenOf is the length of received datagram i, at most the buffer length
// (a larger datagram is truncated to it, as with ReadFromUDP).
func (m *mmsgSocket) lenOf(i int) int { return int(m.hdrs[i].Len) }

// srcOf fills src with the source of received datagram i, reusing src.IP's
// storage (ipBuf), and reports false for an address family it does not
// know. An IPv6 scope is kept as its numeric zone, which the latch copies
// and Go resolves when sending, where ReadFromUDP names the interface.
func (m *mmsgSocket) srcOf(i int, src *net.UDPAddr, ipBuf *[16]byte) bool {
	sa := &m.names[i]
	switch sa.Family {
	case unix.AF_INET:
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		copy(ipBuf[:4], sa4.Addr[:])
		src.IP = ipBuf[:4]
		src.Port = int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa4.Port))[:]))
		src.Zone = ""
	case unix.AF_INET6:
		copy(ipBuf[:], sa.Addr[:])
		src.IP = ipBuf[:16]
		src.Port = int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:]))
		src.Zone = ""
		if sa.Scope_id != 0 {
			src.Zone = strconv.FormatUint(uint64(sa.Scope_id), 10)
		}
	default:
		return false
	}
	return true
}

// queue adds pkt, to dst, as send slot i, and reports false when dst is
// an address the batch does not marshal (a zone, or a family the socket
// cannot reach), which the caller then sends with WriteToUDP.
func (m *mmsgSocket) queue(i int, pkt []byte, dst *net.UDPAddr) bool {
	if dst.Zone != "" || len(pkt) == 0 {
		return false
	}
	sa := &m.names[i]
	*sa = unix.RawSockaddrInet6{}
	ip4 := dst.IP.To4()
	switch {
	case ip4 != nil && !m.inet6:
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		sa4.Family = unix.AF_INET
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa4.Port))[:], uint16(dst.Port))
		copy(sa4.Addr[:], ip4)
		m.hdrs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
	case m.inet6 && dst.IP.To16() != nil:
		// An IPv4 destination on a dual-stack socket goes as v4-mapped,
		// which To16 yields, as Go's own WriteToUDP marshals it.
		sa.Family = unix.AF_INET6
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], uint16(dst.Port))
		copy(sa.Addr[:], dst.IP.To16())
		m.hdrs[i].Hdr.Namelen = unix.SizeofSockaddrInet6
	default:
		return false
	}
	m.iovs[i].Base = &pkt[0]
	m.iovs[i].SetLen(len(pkt))
	m.hdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(sa))
	m.hdrs[i].Hdr.Flags = 0
	m.hdrs[i].Len = 0
	return true
}

// flush sends slots [0, count) with sendmmsg and calls sent with the byte
// count of each datagram the kernel took. A datagram the kernel refuses is
// dropped and the rest still go, which is what one WriteToUDP per packet
// does: sendmmsg stops at the first failing datagram and reports the ones
// before it, so the loop resumes after the failure. A closed socket ends
// the flush silently, like a failed WriteToUDP; the read loop then sees
// the close.
func (m *mmsgSocket) flush(count int, sent func(n int)) {
	m.start = 0
	for m.start < count {
		m.count = count - m.start
		if err := m.rc.Write(m.writeFn); err != nil {
			return // socket closed
		}
		if m.errno != 0 || m.n <= 0 {
			m.start++ // the datagram at start failed: drop it
			continue
		}
		for i := m.start; i < m.start+m.n; i++ {
			sent(int(m.hdrs[i].Len))
		}
		m.start += m.n
	}
}

// relayBatched is relayPlain with recvmmsg and sendmmsg. Every packet goes
// through the same packet() as the plain loop, in arrival order. A batch
// that leaves one packet to send sends it with WriteToUDP, as relayPlain
// does: sendmmsg only pays from two.
func (l *relayLoop) relayBatched() {
	rd, err := newMmsgSocket(l.in)
	if err != nil {
		l.relayPlain()
		return
	}
	wr, err := newMmsgSocket(l.out)
	if err != nil {
		l.relayPlain()
		return
	}
	var bufs [relayBatchSize][]byte
	backing := make([]byte, relayBatchSize*relayBufSize)
	for i := range bufs {
		// Full capacity of the slot, so SRTP can protect in place; the
		// read sees maxPacketSize+1 bytes to detect an oversize datagram.
		bufs[i] = backing[i*relayBufSize : i*relayBufSize+maxPacketSize+1 : (i+1)*relayBufSize]
	}
	rd.bindBufs(&bufs)
	var (
		src   net.UDPAddr
		ipBuf [16]byte
		pkts  [relayBatchSize][]byte
		dsts  [relayBatchSize]*net.UDPAddr
	)
	sent := func(n int) { l.s.counters.recordTx(l.to, l.rtpKind, n) }
	sendOne := func(pkt []byte, dst *net.UDPAddr) {
		if n, err := l.out.WriteToUDP(pkt, dst); err == nil {
			sent(n)
		}
	}
	for {
		n, err := rd.readBatch()
		if err != nil {
			return // socket closed (session teardown)
		}
		pending := 0
		for i := 0; i < n; i++ {
			size := rd.lenOf(i)
			if size > maxPacketSize {
				continue // oversize: forwarding it would forward a truncation
			}
			if !rd.srcOf(i, &src, &ipBuf) {
				continue
			}
			pkt, dst, ok := l.packet(bufs[i][:size], &src)
			if !ok {
				continue
			}
			pkts[pending], dsts[pending] = pkt, dst
			pending++
		}
		if pending == 1 {
			sendOne(pkts[0], dsts[0])
			continue
		}
		// Runs of packets go out in one sendmmsg each; a destination the
		// batch does not marshal goes alone, in order.
		for i := 0; i < pending; {
			k := 0
			for i < pending && wr.queue(k, pkts[i], dsts[i]) {
				k++
				i++
			}
			if k > 0 {
				wr.flush(k, sent)
			}
			if i < pending {
				sendOne(pkts[i], dsts[i])
				i++
			}
		}
	}
}
