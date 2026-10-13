package admin

import (
	"os"
	"path/filepath"
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
