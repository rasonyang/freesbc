package config

import (
	"strings"
	"testing"
)

// proxyYAML is a complete, minimal edge-proxy config: no trunk peers, no
// listen.sip — exactly the "proxy-only" deployment shape.
const proxyYAML = `
network:
  public:
    bind_ip: 0.0.0.0
    advertised_ip: 203.0.113.7
  private:
    bind_ip: 10.77.0.2

sip:
  public:
    udp:
      enabled: true
      bind: 0.0.0.0:16060
    ws:
      enabled: true
      bind: 0.0.0.0:18080
    wss:
      enabled: true
      bind: 0.0.0.0:18443
  private:
    bind: 10.77.0.2:16060
  upstream:
    address: 10.77.0.10:5060
    transport: udp

rtp:
  public:
    bind_ip: 0.0.0.0
    advertised_ip: 203.0.113.7
    port_min: 30000
    port_max: 39999
  private:
    bind_ip: 10.77.0.2
    port_min: 40000
    port_max: 49999

webrtc:
  enabled: true
  ice_mode: lite
  rtcp_mux: true
`

func mustParseProxy(t *testing.T, yaml string) *Config {
	t.Helper()
	c, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

func TestProxyOnlyConfigIsValid(t *testing.T) {
	c := mustParseProxy(t, proxyYAML)
	if !c.ProxyEnabled() {
		t.Fatal("ProxyEnabled() = false")
	}
	if got := len(c.PublicSIPListeners()); got != 3 {
		t.Errorf("public listeners = %d, want 3", got)
	}
	if got := c.PublicAdvertisedIP().String(); got != "203.0.113.7" {
		t.Errorf("PublicAdvertisedIP = %s", got)
	}
	// network.private.advertised_ip is unset, so it falls back to the
	// specific private bind address.
	if got := c.PrivateAdvertisedIP().String(); got != "10.77.0.2" {
		t.Errorf("PrivateAdvertisedIP = %s", got)
	}
	if got := c.PublicRTPAdvertisedIP().String(); got != "203.0.113.7" {
		t.Errorf("PublicRTPAdvertisedIP = %s", got)
	}
	if got := c.PrivateRTPAdvertisedIP().String(); got != "10.77.0.2" {
		t.Errorf("PrivateRTPAdvertisedIP = %s", got)
	}
	if got := c.PrivateSIPAdvertisedPort(); got != 16060 {
		t.Errorf("PrivateSIPAdvertisedPort = %d", got)
	}
}

// A private IP must never be what public clients are told to send to, and
// vice versa: the two advertised planes are resolved from independent
// config and must not bleed into one another.
func TestProxyAdvertisedPlanesAreIndependent(t *testing.T) {
	c := mustParseProxy(t, proxyYAML)
	if c.PublicRTPAdvertisedIP() == c.PrivateRTPAdvertisedIP() {
		t.Fatal("public and private media addresses collapsed to one value")
	}
}

func TestProxyValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{
			"no upstream but listeners configured",
			func(s string) string { return strings.Replace(s, "    address: 10.77.0.10:5060\n", "", 1) },
			"sip.upstream.address: required",
		},
		{
			"upstream transport tcp",
			func(s string) string { return strings.Replace(s, "transport: udp", "transport: tcp", 1) },
			"only \"udp\" is supported",
		},
		{
			"wildcard public bind with no advertised ip",
			func(s string) string { return strings.Replace(s, "    advertised_ip: 203.0.113.7\n", "", 1) },
			"network.public.advertised_ip: required",
		},
		{
			"overlapping media ranges",
			func(s string) string { return strings.Replace(s, "    port_min: 40000", "    port_min: 35000", 1) },
			"overlap",
		},
		{
			"public range inverted",
			func(s string) string { return strings.Replace(s, "    port_max: 39999", "    port_max: 30000", 1) },
			"port_min must be less than port_max",
		},
		{
			"privileged media port",
			func(s string) string { return strings.Replace(s, "    port_min: 30000", "    port_min: 100", 1) },
			"port_min: must be 1024-65535",
		},
		{
			"webrtc without websocket signaling",
			func(s string) string {
				s = strings.Replace(s, "    ws:\n      enabled: true\n      bind: 0.0.0.0:18080\n", "", 1)
				return strings.Replace(s, "    wss:\n      enabled: true\n      bind: 0.0.0.0:18443\n", "", 1)
			},
			"requires sip.public.ws or sip.public.wss",
		},
		{
			"webrtc ice mode full",
			func(s string) string { return strings.Replace(s, "ice_mode: lite", "ice_mode: full", 1) },
			"only \"lite\" is supported",
		},
		{
			"rtcp mux disabled",
			func(s string) string { return strings.Replace(s, "rtcp_mux: true", "rtcp_mux: false", 1) },
			"webrtc.rtcp_mux: must be true",
		},
		{
			"duplicate ws/wss bind",
			func(s string) string { return strings.Replace(s, "bind: 0.0.0.0:18443", "bind: 0.0.0.0:18080", 1) },
			"already bound by",
		},
		{
			"bad upstream address",
			func(s string) string { return strings.Replace(s, "address: 10.77.0.10:5060", "address: 10.77.0.10", 1) },
			"is not \"host:port\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.edit(proxyYAML)))
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

// The trunk B2BUA plane and the edge proxy must be able to coexist in one
// file; the trunk's own media range participates in the overlap check.
func TestProxyAndTrunkCoexist(t *testing.T) {
	both := proxyYAML + `
listen:
  sip: [udp://10.77.0.2:5080]
  media:
    port_range: 20000-20999
peers:
  carrier:
    address: 10.9.0.1:5060
    allowed_ips: [10.9.0.0/16]
routes:
  - name: out
    from: carrier
    to: [carrier]
`
	c := mustParseProxy(t, both)
	if !c.ProxyEnabled() {
		t.Error("proxy plane should still be enabled")
	}
	if len(c.Peers) != 1 {
		t.Error("trunk peers lost")
	}
}

func TestProxyTrunkMediaRangeOverlapRejected(t *testing.T) {
	both := proxyYAML + `
listen:
  sip: [udp://10.77.0.2:5080]
  media:
    port_range: 30500-30999
peers:
  carrier:
    address: 10.9.0.1:5060
    allowed_ips: [10.9.0.0/16]
routes:
  - name: out
    from: carrier
    to: [carrier]
`
	if _, err := Parse([]byte(both)); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("want overlap error, got %v", err)
	}
}

// A trunk-only config must be entirely unaffected by the new sections.
func TestTrunkOnlyConfigUnaffected(t *testing.T) {
	c := mustParseProxy(t, `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: pbx
    to: [pbx]
`)
	if c.ProxyEnabled() {
		t.Error("ProxyEnabled() should be false without sip.upstream")
	}
	if len(c.PublicSIPListeners()) != 0 {
		t.Error("no public listeners expected")
	}
}

func TestHostPortParse(t *testing.T) {
	var h HostPort
	if err := h.UnmarshalYAML([]byte("10.0.0.1:5060")); err != nil {
		t.Fatal(err)
	}
	if h.Host != "10.0.0.1" || h.Port != 5060 {
		t.Fatalf("got %+v", h)
	}
	if h.String() != "10.0.0.1:5060" {
		t.Errorf("String() = %s", h.String())
	}
	for _, bad := range []string{"10.0.0.1", "10.0.0.1:0", "10.0.0.1:99999", "10.0.0.1:abc"} {
		var h HostPort
		if err := h.UnmarshalYAML([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
