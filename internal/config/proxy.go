package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// This file adds the public/private network model of the SIP/RTP/WebRTC
// edge proxy (the "proxy plane"). It is deliberately additive: the trunk
// B2BUA plane keeps its own flat `sip:`/`rtp:` bind/advertised fields and
// its `listen.sip` listener list, and a config may enable either plane or
// both. The proxy plane is active exactly when sip.upstream.address is set
// (see Config.ProxyEnabled).
//
// Naming follows the topology, not the transport: "public" is the side
// facing phones and browsers (SIP/UDP, SIP/WS(S), RTP, WebRTC), "private"
// is the side facing FreeSWITCH (SIP/UDP, plain RTP/RTCP). Every address
// is split into a bind plane (where a socket actually binds) and an
// advertised plane (what we write into Contact/Via/Record-Route and SDP),
// so a NAT'ed or VPN'ed deployment never leaks the wrong address to the
// wrong side.

// HostPort is a "host:port" YAML scalar, e.g. "0.0.0.0:16060".
type HostPort struct {
	Host string
	Port int
}

func (h *HostPort) UnmarshalYAML(b []byte) error {
	s, err := yamlScalarString(b)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", string(b), err)
	}
	if s == "" {
		return nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid address %q: want \"host:port\"", s)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid address %q: bad port", s)
	}
	h.Host, h.Port = host, port
	return nil
}

// IsZero reports whether the address was left unset.
func (h HostPort) IsZero() bool { return h.Host == "" && h.Port == 0 }

// String renders the address back as "host:port".
func (h HostPort) String() string { return net.JoinHostPort(h.Host, strconv.Itoa(h.Port)) }

// NetworkConfig is the top-level `network:` section: the two planes the
// proxy straddles. Both planes' advertised_ip act as the default for the
// matching rtp.public/rtp.private advertised address and for the SIP
// signaling the SBC puts on the wire toward that side.
type NetworkConfig struct {
	Public  NetworkPlane `yaml:"public"`
	Private NetworkPlane `yaml:"private"`
}

// NetworkPlane is one side's bind/advertised address pair.
type NetworkPlane struct {
	BindIP string `yaml:"bind_ip"`
	// AdvertisedIP is what the far side of THIS plane is told to send to.
	// It defaults to BindIP when that is a specific (non-unspecified)
	// address; a wildcard bind requires it to be spelled out.
	AdvertisedIP string `yaml:"advertised_ip"`
}

// ProxySIPConfig is the `sip.public` / `sip.private` / `sip.upstream`
// group. It lives on SIPNetConfig so the YAML keys nest under the existing
// `sip:` section.
type ProxySIPConfig struct {
	UDP ProxyListen `yaml:"udp"`
	WS  ProxyListen `yaml:"ws"`
	WSS ProxyListen `yaml:"wss"`
}

// ProxyListen is one public-facing SIP listener.
type ProxyListen struct {
	Enabled bool     `yaml:"enabled"`
	Bind    HostPort `yaml:"bind"`
	// CertFile/KeyFile are the TLS identity for a wss listener
	// (both-or-neither; ignored for udp/ws).
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// ProxyPrivateSIP is the SBC's own private-side SIP socket: the source of
// every request we send upstream and the destination FreeSWITCH sends its
// own requests (inbound INVITE, in-dialog BYE) to.
type ProxyPrivateSIP struct {
	Bind HostPort `yaml:"bind"`
	// AdvertisedIP overrides network.private.advertised_ip for signaling
	// only (Via/Contact/Record-Route toward FreeSWITCH).
	AdvertisedIP string `yaml:"advertised_ip"`
	// AdvertisedPort overrides Bind.Port in the same headers, for a
	// port-forwarding deployment. Defaults to Bind.Port.
	AdvertisedPort int `yaml:"advertised_port"`
}

// UpstreamConfig points at FreeSWITCH — the authoritative registrar and
// switch behind the SBC.
type UpstreamConfig struct {
	Address   string `yaml:"address"`   // host:port
	Transport string `yaml:"transport"` // udp (the only supported value today)
}

// PstnConfig points at a peer-to-peer PSTN carrier gateway the edge proxy
// forwards FreeSWITCH-bridged outbound calls to. The gateway never
// registers and FreeSBC never sends it keepalives; the only traffic it
// receives is what it is answering. Its zero value disables the trunk.
type PstnConfig struct {
	Address   string   `yaml:"address"`   // host:port; literal IP enforced at topology build
	Transport string   `yaml:"transport"` // udp (default; the only supported value)
	Match     HostPort `yaml:"match"`     // host:port FreeSWITCH bridges PSTN calls to
}

// RTPPlaneConfig is one media plane's bind/advertised address plus its own
// port pool. The two planes MUST use disjoint port ranges when they bind
// the same address family on the same interface, so validation rejects an
// overlap outright rather than letting two pools hand out the same port.
type RTPPlaneConfig struct {
	BindIP       string `yaml:"bind_ip"`
	AdvertisedIP string `yaml:"advertised_ip"`
	PortMin      int    `yaml:"port_min"`
	PortMax      int    `yaml:"port_max"`
}

// configured reports whether the operator wrote anything in this plane.
func (r RTPPlaneConfig) configured() bool {
	return r.BindIP != "" || r.AdvertisedIP != "" || r.PortMin != 0 || r.PortMax != 0
}

// Range returns the plane's port range.
func (r RTPPlaneConfig) Range() PortRange {
	return PortRange{Min: uint16(r.PortMin), Max: uint16(r.PortMax)}
}

// WebRTCConfig turns the browser-facing media leg on.
type WebRTCConfig struct {
	Enabled bool `yaml:"enabled"`
	// ICEMode is "lite" — the only supported mode. FreeSBC has a stable,
	// publicly reachable media address, so it never needs to be a full ICE
	// agent (spec §9). The field exists so a config that spells the mode
	// out validates, and so an unsupported value fails loudly.
	ICEMode string `yaml:"ice_mode"`
	// RTCPMux multiplexes RTCP onto the RTP port toward the browser. This
	// is effectively mandatory for WebRTC and defaults to true; turning it
	// off is rejected because a browser offer without rtcp-mux would need
	// a second ICE component FreeSBC does not implement.
	RTCPMux *bool `yaml:"rtcp_mux"`
	// DTLSCertFile/DTLSKeyFile pin the DTLS identity. When unset, one
	// self-signed ECDSA certificate is generated per process and reused by
	// every session (spec §11).
	DTLSCertFile string `yaml:"dtls_cert_file"`
	DTLSKeyFile  string `yaml:"dtls_key_file"`
}

// RTCPMuxEnabled reports the effective rtcp-mux setting (default true).
func (w WebRTCConfig) RTCPMuxEnabled() bool { return w.RTCPMux == nil || *w.RTCPMux }

// ProxyEnabled reports whether the SIP/RTP/WebRTC edge proxy plane is
// configured. It is the single switch main.go and validation branch on:
// without an upstream there is nothing to proxy to.
func (c *Config) ProxyEnabled() bool { return c.SIP.Upstream.Address != "" }

// PublicSIPListeners returns the enabled public listeners as
// (transport, bind) pairs, in a stable order.
func (c *Config) PublicSIPListeners() []ProxySIPListener {
	var out []ProxySIPListener
	add := func(transport string, l ProxyListen) {
		if l.Enabled {
			out = append(out, ProxySIPListener{Transport: transport, Bind: l.Bind, CertFile: l.CertFile, KeyFile: l.KeyFile})
		}
	}
	add("udp", c.SIP.Public.UDP)
	add("ws", c.SIP.Public.WS)
	add("wss", c.SIP.Public.WSS)
	return out
}

// ProxySIPListener is one resolved public listener.
type ProxySIPListener struct {
	Transport string
	Bind      HostPort
	CertFile  string
	KeyFile   string
}

// PublicAdvertisedIP is the address public clients are told to reach us
// on: network.public.advertised_ip, else the public bind address when it
// is specific. Only meaningful on a validated Config.
func (c *Config) PublicAdvertisedIP() netip.Addr {
	return planeAdvertised(c.Network.Public)
}

// PrivateAdvertisedIP is the address FreeSWITCH is told to reach us on.
func (c *Config) PrivateAdvertisedIP() netip.Addr {
	if ip, err := netip.ParseAddr(c.SIP.Private.AdvertisedIP); err == nil {
		return ip
	}
	return planeAdvertised(c.Network.Private)
}

// PublicRTPAdvertisedIP / PrivateRTPAdvertisedIP are the SDP c=/o=
// addresses for each side: the plane's own rtp.*.advertised_ip when set,
// else the network plane's advertised address.
func (c *Config) PublicRTPAdvertisedIP() netip.Addr {
	if ip, err := netip.ParseAddr(c.RTP.Public.AdvertisedIP); err == nil {
		return ip
	}
	return c.PublicAdvertisedIP()
}

func (c *Config) PrivateRTPAdvertisedIP() netip.Addr {
	if ip, err := netip.ParseAddr(c.RTP.Private.AdvertisedIP); err == nil {
		return ip
	}
	return planeAdvertised(c.Network.Private)
}

func planeAdvertised(p NetworkPlane) netip.Addr {
	if ip, err := netip.ParseAddr(p.AdvertisedIP); err == nil {
		return ip
	}
	if ip, err := netip.ParseAddr(p.BindIP); err == nil && !ip.IsUnspecified() {
		return ip
	}
	return netip.Addr{}
}

// PrivateSIPAdvertisedPort is the port FreeSWITCH sends in-dialog and
// inbound requests to.
func (c *Config) PrivateSIPAdvertisedPort() int {
	if c.SIP.Private.AdvertisedPort != 0 {
		return c.SIP.Private.AdvertisedPort
	}
	return c.SIP.Private.Bind.Port
}

// proxyWithDefaults fills the edge-proxy plane's defaults. It runs
// unconditionally (from withDefaults) but every branch is a no-op unless
// the operator wrote something in the corresponding section, so a
// trunk-only config is untouched.
func proxyWithDefaults(c *Config) {
	if c.SIP.Upstream.Address != "" && c.SIP.Upstream.Transport == "" {
		c.SIP.Upstream.Transport = "udp"
	}
	if c.SIP.Pstn.Address != "" && c.SIP.Pstn.Transport == "" {
		c.SIP.Pstn.Transport = "udp"
	}
	// A public listener written without an explicit bind gets the public
	// plane's bind address and the transport's conventional port, so the
	// minimal config is `sip.public.udp.enabled: true` plus a network block.
	defBind := func(l *ProxyListen, port int) {
		if !l.Enabled || !l.Bind.IsZero() {
			return
		}
		host := c.Network.Public.BindIP
		if host == "" {
			host = "0.0.0.0"
		}
		l.Bind = HostPort{Host: host, Port: port}
	}
	defBind(&c.SIP.Public.UDP, 5060)
	defBind(&c.SIP.Public.WS, 5066)
	defBind(&c.SIP.Public.WSS, 5061)

	if c.ProxyEnabled() && c.SIP.Private.Bind.IsZero() {
		host := c.Network.Private.BindIP
		if host == "" {
			host = "0.0.0.0"
		}
		c.SIP.Private.Bind = HostPort{Host: host, Port: 5060}
	}
	// Each media plane binds its own network plane's address unless told
	// otherwise, so `bind_ip` need only be written once per side.
	if c.RTP.Public.configured() && c.RTP.Public.BindIP == "" {
		c.RTP.Public.BindIP = c.Network.Public.BindIP
	}
	if c.RTP.Private.configured() && c.RTP.Private.BindIP == "" {
		c.RTP.Private.BindIP = c.Network.Private.BindIP
	}
	if c.WebRTC.Enabled && c.WebRTC.ICEMode == "" {
		c.WebRTC.ICEMode = "lite"
	}
}
