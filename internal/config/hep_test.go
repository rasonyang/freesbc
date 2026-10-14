package config

import (
	"strings"
	"testing"
)

func TestHEPAbsentIsOff(t *testing.T) {
	c := mustParse(t, minimalYAML)
	if c.HEP != nil {
		t.Fatalf("HEP = %+v, want nil", c.HEP)
	}
}

func TestHEPDefaults(t *testing.T) {
	c := mustParse(t, with("hep: { address: 10.77.0.50:9060 }\n"))
	h := c.HEP
	if h == nil || h.Transport != HEPUDP || !c.HEPRedact() || h.RedactAuth == nil || !*h.RedactAuth {
		t.Fatalf("defaults = %+v", h)
	}
	off := mustParse(t, with("hep: { address: '[fd00::5]:9060', transport: tcp, redact_auth: false, capture_id: 2001, node_name: edge1 }\n"))
	if off.HEPRedact() || off.HEP.CaptureID != 2001 || off.HEP.NodeName != "edge1" || off.HEP.Transport != HEPTCP {
		t.Fatalf("explicit = %+v", off.HEP)
	}
}

func TestHEPTLSForm(t *testing.T) {
	c := mustParse(t, with(`hep:
  address: 10.77.0.50:9061
  transport: tls
  tls: { ca: /etc/ca.pem, cert: /etc/c.pem, key: /etc/c.key }
`))
	if c.HEP.TLS == nil || c.HEP.TLS.CA != "/etc/ca.pem" || c.HEP.TLS.Key != "/etc/c.key" {
		t.Fatalf("tls = %+v", c.HEP.TLS)
	}
	// tls with no tls block uses the system roots.
	mustParse(t, with("hep: { address: 10.77.0.50:9061, transport: tls }\n"))
}

func TestHEPValidationErrors(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"no address":       {"hep: { transport: udp }\n", "hep.address"},
		"hostname":         {"hep: { address: homer.example:9060 }\n", "hep.address"},
		"no port":          {"hep: { address: 10.77.0.50 }\n", "hep.address"},
		"zero port":        {"hep: { address: 10.77.0.50:0 }\n", "hep.address"},
		"wildcard":         {"hep: { address: 0.0.0.0:9060 }\n", "hep.address"},
		"bad transport":    {"hep: { address: 10.77.0.50:9060, transport: sctp }\n", "hep.transport"},
		"tls on udp":       {"hep: { address: 10.77.0.50:9060, tls: { ca: /x } }\n", "hep.tls: only valid"},
		"cert without key": {"hep: { address: 10.77.0.50:9061, transport: tls, tls: { cert: /c } }\n", "cert and key"},
		"long node":        {"hep: { address: 10.77.0.50:9060, node_name: " + strings.Repeat("n", 300) + " }\n", "hep.node_name"},
	} {
		t.Run(name, func(t *testing.T) {
			if msg := parseErr(t, with(tc.yaml)); !strings.Contains(msg, tc.want) {
				t.Errorf("error %q lacks %q", msg, tc.want)
			}
		})
	}
	// A password is not a thing: HOMER 11 ignores the auth key.
	if msg := parseErr(t, with("hep: { address: 10.77.0.50:9060, password: x }\n")); !strings.Contains(msg, "password") {
		t.Errorf("unknown key error = %q", msg)
	}
}
