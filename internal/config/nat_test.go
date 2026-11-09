package config

import (
	"strings"
	"testing"
)

const natYAML = `
public:
  ip: 203.0.113.7
  bind: 172.20.0.4
private:
  ip: 10.77.0.2
rtp: 16800-16900
tls: { cert: /c.pem, key: /k.pem }
edge:
  switch: [10.77.0.10:5060]
  listen: { udp: 16060, tcp: 16060, tls: 16061, ws: 8080, wss: 7443 }
`

func TestNATChecklist(t *testing.T) {
	c := mustParse(t, natYAML)
	if !c.NATMode() {
		t.Fatal("NATMode = false, want true")
	}
	want := `NAT mode: advertised public endpoint = 203.0.113.7 (udp/16060 tcp/16060 tcp/16061 (tls) tcp/8080 (ws) tcp/7443 (wss) udp/16800-16900 (rtp))
REQUIRED forwards -> 172.20.0.4 (same port numbers):
  udp/16060
  tcp/16060
  tcp/16061 (tls)
  tcp/8080 (ws)
  tcp/7443 (wss)
  udp/16800-16900 (rtp)
in-dialog requests (2xx ACK, BYE) use Contact/Record-Route, not Via:
these ports MUST be reachable from clients.
`
	if got := c.NATChecklist(); got != want {
		t.Errorf("NATChecklist =\n%s\nwant\n%s", got, want)
	}
}

func TestNATChecklistEmptyWithoutNAT(t *testing.T) {
	for name, src := range map[string]string{
		"bind unset": minimalYAML,
		"bind = ip":  replace(t, minimalYAML, "  ip: 203.0.113.7\n", "  ip: 203.0.113.7\n  bind: 203.0.113.7\n"),
	} {
		c := mustParse(t, src)
		if c.NATMode() || c.NATChecklist() != "" || c.NATForwards() != nil {
			t.Errorf("%s: NATMode=%v checklist=%q, want none", name, c.NATMode(), c.NATChecklist())
		}
	}
	if !strings.Contains(mustParse(t, natYAML).NATChecklist(), "REQUIRED") {
		t.Error("NAT checklist lacks REQUIRED")
	}
}
