package admin

import (
	"bufio"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Kernel UDP counters are read at scrape time from /proc. The paths and the
// OS gate are variables so a test can point them at fixtures on any OS.
var (
	procSNMPPath  = "/proc/net/snmp"
	procSNMP6Path = "/proc/net/snmp6"
	udpStatsOS    = runtime.GOOS
)

// udpStats are the kernel's UDP receive-side drop counters for the whole
// network namespace. InErrors already includes RcvbufErrors on Linux.
type udpStats struct {
	RcvbufErrors uint64
	InErrors     uint64
}

// readUDPStats returns IPv4 + IPv6 counters summed. ok is false off Linux or
// when /proc/net/snmp cannot be read or parsed; a missing snmp6 (IPv6
// disabled) leaves IPv4 alone.
func readUDPStats() (udpStats, bool) {
	if udpStatsOS != "linux" {
		return udpStats{}, false
	}
	data, err := os.ReadFile(procSNMPPath)
	if err != nil {
		return udpStats{}, false
	}
	st, ok := parseSNMPUDP(string(data))
	if !ok {
		return udpStats{}, false
	}
	if data6, err := os.ReadFile(procSNMP6Path); err == nil {
		if st6, ok := parseSNMP6UDP(string(data6)); ok {
			st.RcvbufErrors += st6.RcvbufErrors
			st.InErrors += st6.InErrors
		}
	}
	return st, true
}

// parseSNMPUDP reads the two "Udp:" lines of /proc/net/snmp: a header of
// column names, then the values in the same order. ok is false unless both
// counters are found with a well-formed value.
func parseSNMPUDP(s string) (st udpStats, ok bool) {
	var names []string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "Udp:" {
			continue
		}
		if names == nil {
			names = f[1:]
			continue
		}
		vals := f[1:]
		if len(vals) != len(names) {
			return udpStats{}, false
		}
		var gotRcv, gotIn bool
		for i, n := range names {
			if n != "RcvbufErrors" && n != "InErrors" {
				continue
			}
			v, err := strconv.ParseUint(vals[i], 10, 64)
			if err != nil {
				return udpStats{}, false
			}
			if n == "RcvbufErrors" {
				st.RcvbufErrors, gotRcv = v, true
			} else {
				st.InErrors, gotIn = v, true
			}
		}
		if !gotRcv || !gotIn {
			return udpStats{}, false
		}
		return st, true
	}
	return udpStats{}, false
}

// parseSNMP6UDP reads the "Udp6RcvbufErrors" and "Udp6InErrors" name/value
// lines of /proc/net/snmp6. ok is false unless both are present and valid.
func parseSNMP6UDP(s string) (st udpStats, ok bool) {
	var gotRcv, gotIn bool
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || (f[0] != "Udp6RcvbufErrors" && f[0] != "Udp6InErrors") {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return udpStats{}, false
		}
		if f[0] == "Udp6RcvbufErrors" {
			st.RcvbufErrors, gotRcv = v, true
		} else {
			st.InErrors, gotIn = v, true
		}
	}
	if !gotRcv || !gotIn {
		return udpStats{}, false
	}
	return st, true
}

// Per-socket UDP state comes from the kernel's socket tables. /proc/self/net
// is the namespace of this process, the same tables as /proc/net.
var (
	procNetUDPPath  = "/proc/self/net/udp"
	procNetUDP6Path = "/proc/self/net/udp6"
)

// udpSocketStat is the kernel's receive-side view of one UDP socket: bytes
// waiting in its receive queue and datagrams it dropped (sk_drops: mostly a
// full receive buffer, also checksum and filter drops).
type udpSocketStat struct {
	RxQueue uint64
	Drops   uint64
}

// readUDPSockets returns the state of each wanted local address, summed over
// every socket bound to it, from /proc/self/net/udp and udp6. An address
// with no socket in either table is absent from the map. ok is false off
// Linux or when neither table can be read.
func readUDPSockets(want []netip.AddrPort) (map[netip.AddrPort]udpSocketStat, bool) {
	if udpStatsOS != "linux" || len(want) == 0 {
		return nil, false
	}
	set := make(map[netip.AddrPort]bool, len(want))
	for _, ap := range want {
		set[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = true
	}
	out := map[netip.AddrPort]udpSocketStat{}
	read := false
	for _, p := range []string{procNetUDPPath, procNetUDP6Path} {
		f, err := os.Open(p)
		if err != nil {
			continue // udp6 is absent when IPv6 is disabled
		}
		parseProcNetUDP(f, set, out)
		f.Close()
		read = true
	}
	return out, read
}

// parseProcNetUDP scans one /proc/net/udp or udp6 table and adds the
// rx_queue and drops of each socket whose local address is in want to out.
// The header and any line it cannot parse are skipped. Addresses in want
// must be unmapped; an IPv4-mapped IPv6 socket matches its IPv4 address.
// A socket is counted once per table, by inode: the kernel prints the table
// in chunks, and while sockets are bound and closed under load (RTP ports)
// a read can repeat a socket's line, which summing would count twice.
//
//	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
//	 7: 0A00000A:13C4 00000000:0000 07 00000000:00000800 00:00000000 00000000     0        0 4242 2 0000000000000000 12
func parseProcNetUDP(r io.Reader, want map[netip.AddrPort]bool, out map[netip.AddrPort]udpSocketStat) {
	sc := bufio.NewScanner(r)
	seen := map[string]bool{}
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 13 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		local, ok := parseProcNetAddr(f[1])
		if !ok || !want[local] || seen[f[9]] {
			continue
		}
		_, rxHex, ok := strings.Cut(f[4], ":")
		if !ok {
			continue
		}
		rx, err := strconv.ParseUint(rxHex, 16, 64)
		if err != nil {
			continue
		}
		drops, err := strconv.ParseUint(f[len(f)-1], 10, 64)
		if err != nil {
			continue
		}
		seen[f[9]] = true
		st := out[local]
		st.RxQueue += rx
		st.Drops += drops
		out[local] = st
	}
}

// parseProcNetAddr decodes a /proc/net/udp{,6} "ADDR:PORT". The kernel
// prints the address as 32-bit words in host byte order (one word for IPv4,
// four for IPv6), each as %08X, and the port in network order as %04X.
func parseProcNetAddr(s string) (netip.AddrPort, bool) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok || (len(addrHex) != 8 && len(addrHex) != 32) || len(portHex) != 4 {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var b [16]byte
	for i := 0; i < len(addrHex)/8; i++ {
		w, err := strconv.ParseUint(addrHex[i*8:i*8+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		hostEndian.PutUint32(b[i*4:], uint32(w))
	}
	var a netip.Addr
	if len(addrHex) == 8 {
		a = netip.AddrFrom4([4]byte(b[:4]))
	} else {
		a = netip.AddrFrom16(b).Unmap()
	}
	return netip.AddrPortFrom(a, uint16(port)), true
}

// hostEndian is the byte order the kernel prints address words in. A
// variable so a test can check a big-endian host's table.
var hostEndian binary.ByteOrder = binary.NativeEndian
