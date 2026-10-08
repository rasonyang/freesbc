package config

import (
	"slices"
	"strings"
	"testing"
)

// carrierYAML is minimalYAML with the given edge.carriers body (indented
// YAML under "carriers:") and extra edge.listen entries.
func carrierYAML(t *testing.T, listen, carriers string) string {
	t.Helper()
	y := replace(t, minimalYAML, "{ udp: 5060 }", "{ "+listen+" }")
	return y + "  carriers:\n" + carriers
}

func TestCarrierStringAndMappingForms(t *testing.T) {
	c := mustParse(t, carrierYAML(t, "udp: 5060, tcp: 5060, tls: 5061", `    plain: sip.plain.example
    quoted: "198.51.100.4:16060"
    over-tcp: {host: tcp.example, transport: tcp}
    udp-map: {host: 198.51.100.9, transport: udp}
    secure:
      host: sip.secure.example
      transport: tls
      ca_file: /etc/freesbc/ca.pem
      client_cert: /etc/freesbc/client.pem
      client_key: /etc/freesbc/client.key
    secure-port: {host: "198.51.100.5:5070", transport: tls}
`)+"tls: { cert: a, key: b }\n")
	got := map[string]Carrier{}
	for _, k := range c.CarrierList() {
		got[k.Name] = k
	}
	check := func(name, host, transport string, port, dialPort int, explicit bool) {
		t.Helper()
		k, ok := got[name]
		if !ok {
			t.Fatalf("carrier %s missing", name)
		}
		if k.Host != host || k.Transport != transport || k.Port != port || k.DialPort() != dialPort || k.ExplicitPort != explicit {
			t.Errorf("%s = %+v (dial %d), want host %s transport %s port %d dial %d explicit %v",
				name, k, k.DialPort(), host, transport, port, dialPort, explicit)
		}
	}
	check("plain", "sip.plain.example", "udp", 5060, 5060, false)
	check("quoted", "198.51.100.4", "udp", 16060, 16060, true)
	check("over-tcp", "tcp.example", "tcp", 5060, 5060, false)
	check("udp-map", "198.51.100.9", "udp", 5060, 5060, false)
	check("secure", "sip.secure.example", "tls", 5060, 5061, false) // tls default dial port; match port stays 5060
	check("secure-port", "198.51.100.5", "tls", 5070, 5070, true)
	s := got["secure"]
	if s.CAFile != "/etc/freesbc/ca.pem" || s.ClientCert != "/etc/freesbc/client.pem" || s.ClientKey != "/etc/freesbc/client.key" {
		t.Errorf("secure tls settings = %+v", s)
	}
	if !c.Edge.Carriers["plain"].Plain() || c.Edge.Carriers["over-tcp"].Plain() || c.Edge.Carriers["secure"].Plain() {
		t.Error("CarrierConfig.Plain wrong")
	}
}

func TestCarrierErrors(t *testing.T) {
	cases := []struct {
		name, listen, carriers, want string
	}{
		{"unknown key", "udp: 5060", "    a: {host: 1.2.3.4, insecure_skip_verify: true}\n", "mapping of host"},
		{"unknown key is strict", "udp: 5060", "    a: {host: 1.2.3.4, trasport: tcp}\n", "edge.carriers"},
		{"bad transport", "udp: 5060", "    a: {host: 1.2.3.4, transport: sctp}\n", "edge.carriers.a.transport: must be udp, tcp or tls"},
		{"no host", "udp: 5060", "    a: {transport: tcp}\n", "edge.carriers.a"},
		{"udp carrier needs udp listener", "tcp: 5060", "    a: 1.2.3.4\n", "a udp carrier requires edge.listen.udp"},
		{"udp map carrier needs udp listener", "tcp: 5060", "    a: {host: 1.2.3.4, transport: udp}\n", "requires edge.listen.udp"},
		{"ca_file needs tls", "udp: 5060", "    a: {host: 1.2.3.4, transport: tcp, ca_file: /ca.pem}\n", "edge.carriers.a.ca_file: only valid with transport: tls"},
		{"client_cert needs tls", "udp: 5060", "    a: {host: 1.2.3.4, client_cert: /c.pem, client_key: /k.pem}\n", "client_cert: only valid with transport: tls"},
		{"cert without key", "udp: 5060", "    a: {host: 1.2.3.4, transport: tls, client_cert: /c.pem}\n", "client_cert and client_key must be set together"},
		{"key without cert", "udp: 5060", "    a: {host: 1.2.3.4, transport: tls, client_key: /k.pem}\n", "client_cert and client_key must be set together"},
		{"own tls socket", "udp: 5060, tls: 5061", "    a: {host: \"203.0.113.7:5061\", transport: tls}\n", "own public TLS socket"},
		{"dup across transports", "udp: 5060", "    a: 1.2.3.4\n    b: {host: \"1.2.3.4:5060\", transport: tcp}\n", "already used by edge.carriers.a"},
		{"bad host in map", "udp: 5060", "    a: {host: \"bad_host!\", transport: tcp}\n", "edge.carriers.a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := carrierYAML(t, tc.listen, tc.carriers)
			if strings.Contains(tc.listen, "tls:") {
				src += "tls: { cert: a, key: b }\n"
			}
			if err := parseErr(t, src); !strings.Contains(err, tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// A tcp or tls carrier needs no listener: its traffic leaves over
// connections FreeSBC opens.
func TestCarrierStreamNeedsNoListener(t *testing.T) {
	mustParse(t, carrierYAML(t, "udp: 5060", "    a: {host: sip.example, transport: tls}\n    b: {host: tcp.example, transport: tcp}\n"))
	// And a tls carrier needs no top-level tls: that is FreeSBC's server identity.
	mustParse(t, carrierYAML(t, "ws: 8080", "    a: {host: sip.example, transport: tls}\n"))
}

func TestCarrierRestartOnly(t *testing.T) {
	base := carrierYAML(t, "udp: 5060", "    a: {host: sip.example, transport: tls}\n")
	running := mustParse(t, base)
	for name, next := range map[string]string{
		"transport": strings.Replace(base, "transport: tls", "transport: tcp", 1),
		"ca_file":   strings.Replace(base, "transport: tls", "transport: tls, ca_file: /ca.pem", 1),
	} {
		got := RestartOnlyChanges(running, mustParse(t, next))
		if !slices.Equal(got, []string{"edge.carriers"}) {
			t.Errorf("%s: RestartOnlyChanges = %q, want [edge.carriers]", name, got)
		}
	}
}
