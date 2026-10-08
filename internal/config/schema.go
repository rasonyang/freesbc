package config

import (
	"net/netip"
	"time"
)

// PrivateSIPPort is the port of the one fixed private SIP socket,
// private.ip:5060. It is not configurable.
const PrivateSIPPort = 5060

// DefaultCarrierPort is the port assumed for an edge.carriers entry that
// names none.
const DefaultCarrierPort = 5060

// Config is the root of freesbc.yaml (schema v2).
//
// Lifecycle: Parse (the only supported entry point) unmarshals the file
// strictly, expands ${ENV_VAR} references, applies defaults, and validates
// — then the resulting *Config is published via a Store. Snapshots are
// immutable once published: never mutate a *Config after handing it to a
// Store. Compiled fields (Edge.switches, Edge.carrierNets, ...) are
// populated by validate and are only valid on a *Config that has been
// through Parse. Address fields stay strings so they can carry ${VAR}.
type Config struct {
	Public  PublicConfig  `yaml:"public"`
	Private PrivateConfig `yaml:"private"`
	RTP     PortRange     `yaml:"rtp"`
	TLS     *TLSConfig    `yaml:"tls"`
	Edge    EdgeConfig    `yaml:"edge"`
	Shield  ShieldConfig  `yaml:"shield"`
	Admin   *AdminConfig  `yaml:"admin"`

	// envRedact is set by expandEnv: what ${VAR} expansion substituted, so
	// validate can keep expanded values out of its error messages.
	envRedact envRedaction
}

// PublicConfig is the side facing phones, browsers and carriers.
type PublicConfig struct {
	// IP is advertised in Contact/Via/Record-Route/SDP.
	IP string `yaml:"ip"`
	// Bind is the local address every public socket binds. Empty means IP;
	// it differs only behind 1:1 NAT, where IP is not a local address.
	Bind string `yaml:"bind"`
}

// PrivateConfig is the side facing the switch.
type PrivateConfig struct {
	// IP is both the bind and the advertised address.
	IP string `yaml:"ip"`
}

// TLSConfig is the PEM identity used by edge.listen.tls, edge.listen.wss and a
// remote admin.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// ListenPorts are the edge's public ports on public.bind; 0 = not enabled.
type ListenPorts struct {
	UDP int `yaml:"udp"`
	TCP int `yaml:"tcp"`
	TLS int `yaml:"tls"`
	WS  int `yaml:"ws"`
	WSS int `yaml:"wss"`
}

// EdgeConfig is the SIP/RTP/WebRTC edge proxy.
type EdgeConfig struct {
	// Switch lists the switch nodes as literal "IP:port" (UDP). One entry
	// is a single upstream; more is a hash-user pool.
	Switch []string `yaml:"switch"`
	// SwitchCarrierPort is the port on each switch node that receives
	// carrier traffic; 0 (the default) means the node's own switch port.
	SwitchCarrierPort int         `yaml:"switch_carrier_port"`
	Listen            ListenPorts `yaml:"listen"`
	// Carriers maps a carrier name to its "host[:port]" destination.
	Carriers map[string]string `yaml:"carriers"`
	// CarrierSources are extra inbound carrier IPs/CIDRs.
	CarrierSources []string `yaml:"carrier_sources"`

	// Compiled by validate.
	switches    []netip.AddrPort
	carrierNets []netip.Prefix // carrier_sources only
	carriers    []Carrier      // sorted by name
}

// Carrier is one validated edge.carriers entry.
type Carrier struct {
	Name string
	// Host is the lower-cased host as written: a DNS name (no trailing
	// dot) or the canonical literal IP.
	Host string
	Port int
	// ExplicitPort is true when the entry wrote a port. A DNS-name entry
	// without one is resolved through SRV; with one, through A/AAAA only
	// (RFC 3263 §4.2).
	ExplicitPort bool
	// Addr is the literal IP when Host is one, else the zero Addr.
	Addr netip.Addr
}

// Literal reports whether the carrier host is an IP literal.
func (c Carrier) Literal() bool { return c.Addr.IsValid() }

type ShieldConfig struct {
	// RateLimit applies to every public source that is not a carrier.
	RateLimit string `yaml:"rate_limit"`
	// CarrierRateLimit applies to carrier sources.
	CarrierRateLimit string `yaml:"carrier_rate_limit"`
	// Ban is how long a source fingerprinted as a scanner stays banned
	// (in memory only).
	Ban Duration `yaml:"ban"`
	// MaxSessions caps concurrent calls holding a session slot (ringing or
	// up), counted from the first out-of-dialog INVITE. 0 = the number of
	// calls the rtp range can anchor. Hot.
	MaxSessions int `yaml:"max_sessions"`
	// InviteRateLimit is a global limit on new out-of-dialog INVITEs from
	// admitted peers ("<n>/<s|m|h>", no per_ip). Empty = off. Hot.
	InviteRateLimit string `yaml:"invite_rate_limit"`
}

type AdminConfig struct {
	Listen string `yaml:"listen"`
	// PasswordHash is a bcrypt hash (cost >= 10); the user is always "admin".
	PasswordHash string `yaml:"password_hash"`
	// AllowRemote permits a non-loopback listen address, served over HTTPS
	// with the top-level tls identity.
	AllowRemote bool `yaml:"allow_remote"`
	// AllowedHosts are extra host names or IP literals (no port) the admin
	// server accepts in the Host header, besides listen and, on a loopback
	// listen, the loopback names. Optional.
	AllowedHosts []string `yaml:"allowed_hosts"`
}

// AdminUser is the only admin user name.
const AdminUser = "admin"

// DefaultRTP is the RTP range used when rtp is unset.
var DefaultRTP = PortRange{Min: 20000, Max: 29999}

// withDefaults fills spec-defined defaults on a freshly parsed Config.
func withDefaults(c *Config) {
	if c.Public.Bind == "" {
		c.Public.Bind = c.Public.IP
	}
	if c.RTP == (PortRange{}) {
		c.RTP = DefaultRTP
	}
	if c.Shield.MaxSessions == 0 {
		c.Shield.MaxSessions = c.RTP.Pairs()
	}
	if c.Shield.RateLimit == "" {
		c.Shield.RateLimit = "20/s per_ip"
	}
	if c.Shield.CarrierRateLimit == "" {
		c.Shield.CarrierRateLimit = "200/s per_ip"
	}
	if c.Shield.Ban == 0 {
		c.Shield.Ban = Duration(time.Hour)
	}
}

// PublicIP is the address advertised to public peers. Only meaningful on a
// validated Config.
func (c *Config) PublicIP() netip.Addr { return mustAddr(c.Public.IP) }

// PublicBind is the local address every public socket binds.
func (c *Config) PublicBind() netip.Addr { return mustAddr(c.Public.Bind) }

// PrivateIP is the private bind and advertised address.
func (c *Config) PrivateIP() netip.Addr { return mustAddr(c.Private.IP) }

// PrivateAddr is the fixed private SIP socket, private.ip:5060.
func (c *Config) PrivateAddr() netip.AddrPort {
	return netip.AddrPortFrom(c.PrivateIP(), PrivateSIPPort)
}

// Switches returns the edge.switch nodes in file order.
func (c *Config) Switches() []netip.AddrPort { return c.Edge.switches }

// CarrierNets returns every address range that is an inbound carrier
// source known without DNS: edge.carrier_sources plus the literal-IP
// carriers as host prefixes.
func (c *Config) CarrierNets() []netip.Prefix {
	out := append([]netip.Prefix(nil), c.Edge.carrierNets...)
	for _, k := range c.Edge.carriers {
		if k.Literal() {
			out = append(out, netip.PrefixFrom(k.Addr, k.Addr.BitLen()))
		}
	}
	return out
}

// CarrierList returns the edge.carriers entries sorted by name.
func (c *Config) CarrierList() []Carrier { return c.Edge.carriers }

// WebRTC reports whether the edge serves WebSocket clients (any of
// edge.listen.ws/wss is set), which enables WebRTC.
func (c *Config) WebRTC() bool { return c.Edge.Listen.WS != 0 || c.Edge.Listen.WSS != 0 }

func mustAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a.Unmap()
}
