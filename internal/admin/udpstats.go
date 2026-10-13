package admin

import (
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
