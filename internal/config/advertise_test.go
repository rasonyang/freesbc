package config

import (
	"strings"
	"testing"
)

// advertiseYAML is minimalYAML with every transport listening and two of
// them advertised on other ports (a NAT that translates 16060 -> 5060 and
// 16061 -> 5061).
func advertiseYAML(t *testing.T) string {
	t.Helper()
	return replace(t, minimalYAML, "listen: { udp: 5060 }",
		"listen: { udp: 5060, tcp: 5060, tls: 5061, ws: 8080, wss: 8443 }\n  advertise: { udp: 16060, tls: 16061 }") +
		"tls: { cert: a, key: b }\n"
}

func TestAdvertisedPort(t *testing.T) {
	c := mustParse(t, advertiseYAML(t))
	for tr, want := range map[string]int{"udp": 16060, "tcp": 5060, "tls": 16061, "ws": 8080, "wss": 8443, "sctp": 0} {
		if got := c.AdvertisedPort(tr); got != want {
			t.Errorf("AdvertisedPort(%s) = %d, want %d", tr, got, want)
		}
	}
	// The listen ports are untouched: they are what binds.
	if c.Edge.Listen.UDP != 5060 || c.Edge.Listen.TLS != 5061 {
		t.Errorf("listen = %+v", c.Edge.Listen)
	}
	if !c.PortTranslated() {
		t.Error("PortTranslated = false with edge.advertise set")
	}

	plain := mustParse(t, minimalYAML)
	if plain.AdvertisedPort("udp") != 5060 || plain.AdvertisedPort("tcp") != 0 {
		t.Errorf("without advertise: udp=%d tcp=%d, want 5060 and 0", plain.AdvertisedPort("udp"), plain.AdvertisedPort("tcp"))
	}
	if plain.PortTranslated() {
		t.Error("PortTranslated = true without edge.advertise")
	}
	// Advertising the listen port itself is allowed and is no translation.
	same := mustParse(t, replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  advertise: { udp: 5060 }"))
	if same.PortTranslated() || same.NATMode() {
		t.Error("advertise equal to listen counted as a translation")
	}
}

func TestAdvertiseValidateErrors(t *testing.T) {
	adv := func(listen, advertise string) string {
		return replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: "+listen+"\n  advertise: "+advertise) +
			"tls: { cert: a, key: b }\n"
	}
	cases := []struct{ name, src, want string }{
		{"port range", adv("{ udp: 5060 }", "{ udp: 70000 }"), "edge.advertise.udp: must be 1-65535, got 70000"},
		{"negative", adv("{ udp: 5060 }", "{ udp: -1 }"), "edge.advertise.udp: must be 1-65535"},
		{"no listener", adv("{ udp: 5060 }", "{ tcp: 15060 }"), "edge.advertise.tcp: edge.listen.tcp is not set"},
		{"no ws listener", adv("{ udp: 5060 }", "{ wss: 443 }"), "edge.advertise.wss: edge.listen.wss is not set"},
		{"unknown key", adv("{ udp: 5060 }", "{ sctp: 5060 }"), "sctp"},
		{"stream ports collide", adv("{ tcp: 5060, tls: 5061 }", "{ tls: 5060 }"), "edge.advertise.tls: port 5060 is already advertised by edge.listen.tcp"},
		{"two advertised collide", adv("{ ws: 8080, wss: 8443 }", "{ ws: 443, wss: 443 }"), "edge.advertise.wss: port 443 is already advertised by edge.advertise.ws"},
		{"carrier is advertised socket", replace(t, adv("{ udp: 5060 }", "{ udp: 16060 }"), "advertise: { udp: 16060 }",
			"advertise: { udp: 16060 }\n  carriers: { a: \"203.0.113.7:16060\" }"), "own public UDP socket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := parseErr(t, tc.src); !strings.Contains(err, tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
	// Every error is reported in one pass.
	err := parseErr(t, adv("{ udp: 5060 }", "{ udp: 70000, tcp: 1 }"))
	for _, want := range []string{"edge.advertise.udp", "edge.advertise.tcp"} {
		if !strings.Contains(err, want) {
			t.Errorf("aggregated error %q lacks %q", err, want)
		}
	}
}

func TestAdvertiseValidateAccepts(t *testing.T) {
	for name, src := range map[string]string{
		"all translated": advertiseYAML(t),
		// udp is its own port space: it may advertise the number tcp does.
		"udp shares tcp's advertised port": replace(t, minimalYAML, "listen: { udp: 5060 }",
			"listen: { udp: 5060, tcp: 5070 }\n  advertise: { udp: 16060, tcp: 16060 }"),
		// Swapping two stream ports is fine: each advertised port is distinct.
		"swapped stream ports": replace(t, minimalYAML, "listen: { udp: 5060 }",
			"listen: { tcp: 5060, ws: 8080 }\n  advertise: { tcp: 8080, ws: 5060 }"),
		// Behind 1:1 NAT the listen port on public.ip is the router's, not
		// FreeSBC's, once another port is advertised, so a carrier may sit
		// there.
		"carrier at the listen port on public.ip": replace(t, replace(t, minimalYAML, "  ip: 203.0.113.7\n", "  ip: 203.0.113.7\n  bind: 172.20.0.4\n"),
			"listen: { udp: 5060 }", "listen: { udp: 5060 }\n  advertise: { udp: 16060 }\n  carriers: { a: \"203.0.113.7:5060\" }"),
	} {
		t.Run(name, func(t *testing.T) { mustParse(t, src) })
	}
}

// Port translation alone (public.bind = public.ip) is NAT mode, and the
// checklist names each translated forward external->internal while the rtp
// range keeps its numbers.
func TestNATChecklistWithAdvertise(t *testing.T) {
	c := mustParse(t, replace(t, natYAML, "listen: { udp: 16060, tcp: 16060, tls: 16061, ws: 8080, wss: 7443 }",
		"listen: { udp: 5060, tcp: 5060, tls: 5061, ws: 8080, wss: 7443 }\n  advertise: { udp: 16060, tcp: 16060, tls: 16061 }"))
	want := `NAT mode: advertised public endpoint = 223.76.90.4 (udp/16060->5060 tcp/16060->5060 tcp/16061->5061 (tls) tcp/8080 (ws) tcp/7443 (wss) udp/16800-16900 (rtp))
REQUIRED forwards -> 172.20.0.4 (external->internal where shown, else the same port number; the rtp range is never translated):
  udp/16060->5060
  tcp/16060->5060
  tcp/16061->5061 (tls)
  tcp/8080 (ws)
  tcp/7443 (wss)
  udp/16800-16900 (rtp)
in-dialog requests (2xx ACK, BYE) use Contact/Record-Route, not Via:
these ports MUST be reachable from clients.
`
	if got := c.NATChecklist(); got != want {
		t.Errorf("NATChecklist =\n%s\nwant\n%s", got, want)
	}

	noBind := mustParse(t, replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  advertise: { udp: 16060 }"))
	if !noBind.NATMode() {
		t.Fatal("NATMode = false with a translated port")
	}
	if got := noBind.NATChecklist(); !strings.Contains(got, "  udp/16060->5060\n") || !strings.Contains(got, "-> 203.0.113.7") {
		t.Errorf("checklist without public.bind:\n%s", got)
	}
}
