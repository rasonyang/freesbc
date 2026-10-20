package admin

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const snmpFixture = `Ip: Forwarding DefaultTTL
Ip: 1 64
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 100 2 30 90 25 1 0 0 0
UdpLite: InDatagrams NoPorts InErrors
UdpLite: 0 0 0
`

const snmp6Fixture = `Ip6InReceives                   	10
Udp6InDatagrams                 	5
Udp6InErrors                    	7
Udp6RcvbufErrors                	4
Udp6SndbufErrors                	0
`

func TestParseSNMPUDP(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want udpStats
		ok   bool
	}{
		{"normal", snmpFixture, udpStats{RcvbufErrors: 25, InErrors: 30}, true},
		{"no trailing newline", strings.TrimSuffix(snmpFixture, "\n"), udpStats{RcvbufErrors: 25, InErrors: 30}, true},
		{"missing RcvbufErrors column", "Udp: InDatagrams InErrors\nUdp: 1 2\n", udpStats{}, false},
		{"missing InErrors column", "Udp: InDatagrams RcvbufErrors\nUdp: 1 2\n", udpStats{}, false},
		{"fewer values than names", "Udp: InDatagrams InErrors RcvbufErrors\nUdp: 1 2\n", udpStats{}, false},
		{"more values than names", "Udp: InErrors RcvbufErrors\nUdp: 1 2 3\n", udpStats{}, false},
		{"non-numeric value", "Udp: InErrors RcvbufErrors\nUdp: 1 x\n", udpStats{}, false},
		{"negative value", "Udp: InErrors RcvbufErrors\nUdp: 1 -2\n", udpStats{}, false},
		{"header only", "Udp: InErrors RcvbufErrors\n", udpStats{}, false},
		{"no Udp lines", "Ip: Forwarding\nIp: 1\nUdpLite: InErrors\nUdpLite: 1\n", udpStats{}, false},
		{"empty", "", udpStats{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSNMPUDP(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("parseSNMPUDP = %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestParseSNMP6UDP(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want udpStats
		ok   bool
	}{
		{"normal", snmp6Fixture, udpStats{RcvbufErrors: 4, InErrors: 7}, true},
		{"missing one counter", "Udp6InErrors 7\n", udpStats{}, false},
		{"non-numeric value", "Udp6InErrors 7\nUdp6RcvbufErrors z\n", udpStats{}, false},
		{"UdpLite6 ignored", "UdpLite6InErrors 9\n", udpStats{}, false},
		{"empty", "", udpStats{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSNMP6UDP(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("parseSNMP6UDP = %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// useUDPFixtures points the collector at fixture files (empty content means
// the file is absent) and at the given OS for the duration of the test.
func useUDPFixtures(t *testing.T, goos, snmp, snmp6 string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if content != "" {
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	oldA, oldB, oldOS := procSNMPPath, procSNMP6Path, udpStatsOS
	procSNMPPath, procSNMP6Path, udpStatsOS = write("snmp", snmp), write("snmp6", snmp6), goos
	t.Cleanup(func() { procSNMPPath, procSNMP6Path, udpStatsOS = oldA, oldB, oldOS })
}

func TestMetricsUDPKernelCounters(t *testing.T) {
	for _, tc := range []struct {
		name, goos, snmp, snmp6 string
		want                    []string // empty: the series must be absent
	}{
		{"v4 and v6 summed", "linux", snmpFixture, snmp6Fixture,
			[]string{"freesbc_udp_receive_buffer_errors_total 29\n", "freesbc_udp_in_errors_total 37\n"}},
		{"no snmp6", "linux", snmpFixture, "",
			[]string{"freesbc_udp_receive_buffer_errors_total 25\n", "freesbc_udp_in_errors_total 30\n"}},
		{"bad snmp6 ignored", "linux", snmpFixture, "Udp6InErrors x\n",
			[]string{"freesbc_udp_receive_buffer_errors_total 25\n", "freesbc_udp_in_errors_total 30\n"}},
		{"unreadable snmp", "linux", "", snmp6Fixture, nil},
		{"unparsable snmp", "linux", "garbage\n", snmp6Fixture, nil},
		{"not linux", "darwin", snmpFixture, snmp6Fixture, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useUDPFixtures(t, tc.goos, tc.snmp, tc.snmp6)
			body := string(authGET(t, testServer(t), "/metrics"))
			if tc.want == nil {
				if strings.Contains(body, "freesbc_udp_") {
					t.Fatalf("/metrics exports a freesbc_udp_ series\n---\n%s", body)
				}
				return
			}
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("/metrics missing %q", w)
				}
			}
			if !strings.Contains(body, "# TYPE freesbc_udp_in_errors_total counter") {
				t.Error("freesbc_udp_in_errors_total is not a counter")
			}
		})
	}
}

// procNetUDPFixture is /proc/net/udp on a little-endian host: the private
// socket 10.0.0.10:5060 twice (two sockets on one address are summed), the
// public 203.0.113.7:5060, the same public IP on another port, and
// malformed lines.
const procNetUDPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   7: 0A00000A:13C4 00000000:0000 07 00000000:00000800 00:00000000 00000000     0        0 4242 2 0000000000000000 12
   8: 0A00000A:13C4 00000000:0000 07 00000000:00000100 00:00000000 00000000     0        0 4243 2 0000000000000000 3
   9: 077100CB:13C4 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4244 2 0000000000000000 40
  10: 077100CB:4E20 00000000:0000 07 00000000:00001000 00:00000000 00000000     0        0 4245 2 0000000000000000 999
  11: 077100CB:13C4 00000000:0000 07 00000000:zz 00:00000000 00000000     0        0 4246 2 0000000000000000 5
  12: 077100CB:13C4 00000000:0000 07 00000000:00000001 00:00000000 00000000     0        0 4247 2 0000000000000000 -1
  13: 077100CB:13C4 00000000:0000 07 00000000:00000001
  14: 77100CB:13C4 00000000:0000 07 00000000:00000001 00:00000000 00000000     0        0 4248 2 0000000000000000 7
garbage
`

// procNetUDP6Fixture is /proc/net/udp6 on a little-endian host: 2001:db8::5
// port 5060 and an IPv4-mapped ::ffff:10.0.0.10 port 5060.
const procNetUDP6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   1: B80D0120000000000000000005000000:13C4 00000000000000000000000000000000:0000 07 00000000:00000200 00:00000000 00000000     0        0 5001 2 0000000000000000 6
   2: 0000000000000000FFFF00000A00000A:13C4 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 5002 2 0000000000000000 100
   3: B80D0120000000000000000005000000:13C5 00000000000000000000000000000000:0000 07 00000000:00000200 00:00000000 00000000     0        0 5003 2 0000000000000000 8
`

func useLittleEndian(t *testing.T) {
	t.Helper()
	old := hostEndian
	hostEndian = binary.LittleEndian
	t.Cleanup(func() { hostEndian = old })
}

func TestParseProcNetAddr(t *testing.T) {
	useLittleEndian(t)
	for _, tc := range []struct {
		in   string
		want string // "" means not ok
	}{
		{"0100007F:13C4", "127.0.0.1:5060"},
		{"077100CB:13C4", "203.0.113.7:5060"},
		{"0A00000A:0000", "10.0.0.10:0"},
		{"B80D0120000000000000000005000000:13C4", "[2001:db8::5]:5060"},
		{"0000000000000000FFFF00000A00000A:13C4", "10.0.0.10:5060"},
		{"00000000000000000000000001000000:FFFF", "[::1]:65535"},
		{"77100CB:13C4", ""},
		{"0100007F:13C", ""},
		{"0100007F13C4", ""},
		{"0100007G:13C4", ""},
		{"0100007F:13CZ", ""},
		{"B80D012000000000000000000500000:13C4", ""},
		{"", ""},
	} {
		got, ok := parseProcNetAddr(tc.in)
		if tc.want == "" {
			if ok {
				t.Errorf("parseProcNetAddr(%q) = %v, want not ok", tc.in, got)
			}
			continue
		}
		if !ok || got.String() != tc.want {
			t.Errorf("parseProcNetAddr(%q) = %v, %v; want %s", tc.in, got, ok, tc.want)
		}
	}
}

// A big-endian host prints the address words in network order.
func TestParseProcNetAddrBigEndian(t *testing.T) {
	old := hostEndian
	hostEndian = binary.BigEndian
	t.Cleanup(func() { hostEndian = old })
	for in, want := range map[string]string{
		"CB007107:13C4":                         "203.0.113.7:5060",
		"20010DB8000000000000000000000005:13C4": "[2001:db8::5]:5060",
	} {
		if got, ok := parseProcNetAddr(in); !ok || got.String() != want {
			t.Errorf("parseProcNetAddr(%q) = %v, %v; want %s", in, got, ok, want)
		}
	}
}

func TestParseProcNetUDP(t *testing.T) {
	useLittleEndian(t)
	priv := netip.MustParseAddrPort("10.0.0.10:5060")
	pub := netip.MustParseAddrPort("203.0.113.7:5060")
	v6 := netip.MustParseAddrPort("[2001:db8::5]:5060")
	want := map[netip.AddrPort]bool{priv: true, pub: true, v6: true}
	out := map[netip.AddrPort]udpSocketStat{}
	parseProcNetUDP(strings.NewReader(procNetUDPFixture), want, out)
	parseProcNetUDP(strings.NewReader(procNetUDP6Fixture), want, out)
	exp := map[netip.AddrPort]udpSocketStat{
		priv: {RxQueue: 0x900, Drops: 115}, // two IPv4 sockets + the IPv4-mapped one
		pub:  {RxQueue: 0, Drops: 40},      // port 20000 and the malformed lines skipped
		v6:   {RxQueue: 0x200, Drops: 6},   // port 5061 skipped
	}
	if len(out) != len(exp) {
		t.Fatalf("parseProcNetUDP = %+v; want %+v", out, exp)
	}
	for ap, w := range exp {
		if out[ap] != w {
			t.Errorf("%v: got %+v, want %+v", ap, out[ap], w)
		}
	}
}

// A socket whose line the kernel printed twice in one read (same inode) is
// counted once; another socket on the same address still adds.
func TestParseProcNetUDPRepeatedLine(t *testing.T) {
	useLittleEndian(t)
	priv := netip.MustParseAddrPort("10.0.0.10:5060")
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   7: 0A00000A:13C4 00000000:0000 07 00000000:00000800 00:00000000 00000000     0        0 4242 2 0000000000000000 12
   7: 0A00000A:13C4 00000000:0000 07 00000000:00000800 00:00000000 00000000     0        0 4242 2 0000000000000000 12
   8: 0A00000A:13C4 00000000:0000 07 00000000:00000100 00:00000000 00000000     0        0 4243 2 0000000000000000 3
`
	out := map[netip.AddrPort]udpSocketStat{}
	parseProcNetUDP(strings.NewReader(table), map[netip.AddrPort]bool{priv: true}, out)
	if w := (udpSocketStat{RxQueue: 0x900, Drops: 15}); out[priv] != w {
		t.Fatalf("got %+v, want %+v", out[priv], w)
	}
}

// useUDPSocketFixtures points the per-socket reader at fixture tables (empty
// content means the file is absent), little-endian, on the given OS.
func useUDPSocketFixtures(t *testing.T, goos, udp, udp6 string) {
	t.Helper()
	useLittleEndian(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if content != "" {
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	oldA, oldB, oldOS := procNetUDPPath, procNetUDP6Path, udpStatsOS
	oldS, oldS6 := procSNMPPath, procSNMP6Path
	procNetUDPPath, procNetUDP6Path, udpStatsOS = write("udp", udp), write("udp6", udp6), goos
	procSNMPPath, procSNMP6Path = write("snmp", ""), write("snmp6", "") // absent: only the per-socket series
	t.Cleanup(func() {
		procNetUDPPath, procNetUDP6Path, udpStatsOS = oldA, oldB, oldOS
		procSNMPPath, procSNMP6Path = oldS, oldS6
	})
}

func TestMetricsUDPSocketCounters(t *testing.T) {
	listeners := func() []Listener {
		return []Listener{
			{Transport: "udp", Bind: "203.0.113.7:5060", Advertised: "198.51.100.1:5060"},
			{Transport: "tcp", Bind: "203.0.113.7:5060", Advertised: "198.51.100.1:5060"},
			{Transport: "udp", Bind: "10.0.0.10:5060", Advertised: "10.0.0.10:5060", Private: true},
		}
	}
	for _, tc := range []struct {
		name, goos, udp, udp6 string
		want                  []string // empty: no per-socket series
	}{
		{"both tables", "linux", procNetUDPFixture, procNetUDP6Fixture, []string{
			`freesbc_udp_socket_drops_total{socket="private"} 115` + "\n",
			`freesbc_udp_socket_drops_total{socket="public"} 40` + "\n",
			`freesbc_udp_socket_rx_queue_bytes{socket="private"} 2304` + "\n",
			`freesbc_udp_socket_rx_queue_bytes{socket="public"} 0` + "\n",
		}},
		{"no udp6", "linux", procNetUDPFixture, "", []string{
			`freesbc_udp_socket_drops_total{socket="private"} 15` + "\n",
			`freesbc_udp_socket_drops_total{socket="public"} 40` + "\n",
		}},
		{"private only in udp6", "linux", "", procNetUDP6Fixture, []string{
			`freesbc_udp_socket_drops_total{socket="private"} 100` + "\n",
		}},
		{"no tables", "linux", "", "", nil},
		{"not linux", "darwin", procNetUDPFixture, procNetUDP6Fixture, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useUDPSocketFixtures(t, tc.goos, tc.udp, tc.udp6)
			deps := emptyDeps()
			deps.ListenerInfos = listeners
			body := string(authGET(t, newTestServer(t, deps), "/metrics"))
			if tc.want == nil {
				if strings.Contains(body, "freesbc_udp_socket_") {
					t.Fatalf("/metrics exports a freesbc_udp_socket_ series\n---\n%s", body)
				}
				return
			}
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("/metrics missing %q\n---\n%s", w, body)
				}
			}
			if tc.name == "private only in udp6" && strings.Contains(body, `socket="public"`) {
				t.Error("a socket missing from both tables exports a series")
			}
			if !strings.Contains(body, "# TYPE freesbc_udp_socket_drops_total counter") ||
				!strings.Contains(body, "# TYPE freesbc_udp_socket_rx_queue_bytes gauge") {
				t.Error("wrong metric types")
			}
		})
	}
}

// On Linux the reader finds a real socket in the kernel's own table (this
// checks the address decoding against the host's byte order) and sees the
// datagrams a full receive buffer dropped.
func TestReadUDPSocketsLive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc/self/net/udp")
	}
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1"
			if network == "udp6" {
				host = "::1"
			}
			rx, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
			if err != nil {
				t.Skipf("no %s loopback: %v", network, err)
			}
			defer rx.Close()
			if err := rx.(*net.UDPConn).SetReadBuffer(1); err != nil { // the kernel's minimum
				t.Fatal(err)
			}
			tx, err := net.Dial(network, rx.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Close()
			payload := make([]byte, 1000)
			for range 200 {
				_, _ = tx.Write(payload)
			}
			ap := rx.LocalAddr().(*net.UDPAddr).AddrPort()
			got, ok := readUDPSockets([]netip.AddrPort{ap})
			if !ok {
				t.Fatal("readUDPSockets not ok on Linux")
			}
			st, found := got[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]
			if !found {
				t.Fatalf("%v not in /proc/self/net/%s: %+v", ap, network, got)
			}
			if st.Drops == 0 || st.RxQueue == 0 {
				t.Fatalf("%v: %+v; want drops and a queued backlog", ap, st)
			}
		})
	}
}
