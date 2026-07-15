package config

import (
	"net/netip"
	"regexp"
	"time"
)

// Config is the root of sbc.yaml. Snapshots are immutable once published:
// never mutate a *Config after handing it to a Store.
type Config struct {
	Listen ListenConfig     `yaml:"listen"`
	Peers  map[string]*Peer `yaml:"peers"`
	Routes []*Route         `yaml:"routes"`
	Shield ShieldConfig     `yaml:"shield"`
	Admin  *AdminConfig     `yaml:"admin"`
}

type ListenConfig struct {
	SIP   []SIPListen `yaml:"sip"`
	Media MediaConfig `yaml:"media"`
}

type MediaConfig struct {
	PortRange PortRange `yaml:"port_range"`
	PublicIP  string    `yaml:"public_ip"` // "auto" (STUN-detected) or a literal IP
}

// Peer is a SIP trunk counterpart (carrier or PBX).
type Peer struct {
	Address    string    `yaml:"address"`
	Transport  string    `yaml:"transport"` // udp (default), tcp, tls
	Auth       *PeerAuth `yaml:"auth"`
	Register   bool      `yaml:"register"` // outbound REGISTER to this peer
	AllowedIPs []string  `yaml:"allowed_ips"`

	allowedNets []netip.Prefix // compiled by Validate
}

// AllowsIP reports whether addr matches one of the peer's allowed_ips
// prefixes. Only valid after Validate has run.
func (p *Peer) AllowsIP(addr netip.Addr) bool {
	for _, n := range p.allowedNets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

type PeerAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Route is one routing rule; first match wins, list order is failover order.
type Route struct {
	Name      string          `yaml:"name"`
	From      string          `yaml:"from"`
	Match     *RouteMatch     `yaml:"match"`
	Transform *RouteTransform `yaml:"transform"`
	To        []string        `yaml:"to"`

	matchTo *regexp.Regexp // compiled by Validate
}

// CompiledMatch returns the compiled match.to regex, or nil when the route
// has no match clause. Only valid after Validate has run.
func (r *Route) CompiledMatch() *regexp.Regexp { return r.matchTo }

type RouteMatch struct {
	To string `yaml:"to"`
}

type RouteTransform struct {
	To string `yaml:"to"`
}

type ShieldConfig struct {
	RateLimit string  `yaml:"rate_limit"`
	AutoBan   AutoBan `yaml:"auto_ban"`
	NFTables  string  `yaml:"nftables"` // auto, on, off
}

type AutoBan struct {
	Failures int      `yaml:"failures"`
	Window   Duration `yaml:"window"`
	Duration Duration `yaml:"duration"`
}

type AdminConfig struct {
	Listen string    `yaml:"listen"`
	Auth   AdminAuth `yaml:"auth"`
}

type AdminAuth struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// withDefaults fills spec-defined defaults on a freshly parsed Config.
func withDefaults(c *Config) {
	if c.Listen.Media.PortRange == (PortRange{}) {
		c.Listen.Media.PortRange = PortRange{Min: 16384, Max: 32768}
	}
	if c.Listen.Media.PublicIP == "" {
		c.Listen.Media.PublicIP = "auto"
	}
	for _, p := range c.Peers {
		if p.Transport == "" {
			p.Transport = "udp"
		}
	}
	if c.Shield.RateLimit == "" {
		c.Shield.RateLimit = "20/s per_ip"
	}
	if c.Shield.AutoBan.Failures == 0 {
		c.Shield.AutoBan.Failures = 5
	}
	if c.Shield.AutoBan.Window == 0 {
		c.Shield.AutoBan.Window = Duration(60 * time.Second)
	}
	if c.Shield.AutoBan.Duration == 0 {
		c.Shield.AutoBan.Duration = Duration(time.Hour)
	}
	if c.Shield.NFTables == "" {
		c.Shield.NFTables = "auto"
	}
}
