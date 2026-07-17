package config

import (
	"net/netip"
	"regexp"
	"time"
)

// Config is the root of sbc.yaml.
//
// Lifecycle: Parse (the only supported entry point) unmarshals the file,
// expands ${ENV_VAR} references, applies defaults, and validates — then the
// resulting *Config is published via a Store. Snapshots are immutable once
// published: never mutate a *Config after handing it to a Store. Compiled
// fields (Peer.allowedNets, Route.matchTo) are populated by validate and are
// only valid on a *Config that has been through Parse.
type Config struct {
	Listen          ListenConfig     `yaml:"listen"`
	Peers           map[string]*Peer `yaml:"peers"`
	Routes          []*Route         `yaml:"routes"`
	Shield          ShieldConfig     `yaml:"shield"`
	Admin           *AdminConfig     `yaml:"admin"`
	RingTimeout     Duration         `yaml:"ring_timeout"`     // cancel a ringing target after this long, then failover
	RegisterExpires Duration         `yaml:"register_expires"` // requested REGISTER lifetime (carrier may grant less)
	SessionExpires  Duration         `yaml:"session_expires"`  // RFC 4028 Session-Expires we advertise/accept
	MinSE           Duration         `yaml:"min_se"`           // minimum session interval accepted (else 422)
	PeerCooldown    Duration         `yaml:"peer_cooldown"`    // skip a peer endpoint this long after a connect failure
	SRVCacheTTL     Duration         `yaml:"srv_cache_ttl"`    // cache DNS SRV/endpoint resolutions this long (stdlib exposes no record TTL)
}

type ListenConfig struct {
	SIP   []SIPListen `yaml:"sip"`
	Media MediaConfig `yaml:"media"`
}

type MediaConfig struct {
	PortRange  PortRange `yaml:"port_range"`
	PublicIP   string    `yaml:"public_ip"`   // "auto" (STUN-detected) or a literal IP
	RTPTimeout Duration  `yaml:"rtp_timeout"` // tear down a call after this much RTP silence
}

// Peer is a SIP trunk counterpart (carrier or PBX).
type Peer struct {
	Address    string    `yaml:"address"`
	Transport  string    `yaml:"transport"` // udp (default), tcp, tls
	Auth       *PeerAuth `yaml:"auth"`
	Register   bool      `yaml:"register"` // outbound REGISTER to this peer
	AllowedIPs []string  `yaml:"allowed_ips"`
	// MediaLatch controls first-packet latching for this peer's media:
	// "strict" (default) requires the first RTP packet's source IP to match
	// the SDP-signaled address; "loose" accepts any source (hard NAT).
	MediaLatch string `yaml:"media_latch"`
	// SRTP is this peer's media-encryption policy: "disabled" (default,
	// plaintext RTP), "optional" (SRTP if offered/accepted, else RTP), or
	// "required" (RTP/SAVP + a=crypto mandatory, else the leg fails). See M5.
	SRTP string `yaml:"srtp"`
	// RegisterExpires overrides the global register_expires for this peer
	// (0 = use the global default). Only meaningful with register: true.
	RegisterExpires Duration `yaml:"register_expires"`

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
	if c.Listen.Media.RTPTimeout == 0 {
		c.Listen.Media.RTPTimeout = Duration(5 * time.Minute)
	}
	for _, p := range c.Peers {
		if p.Transport == "" {
			p.Transport = "udp"
		}
		if p.MediaLatch == "" {
			p.MediaLatch = "strict"
		}
		if p.SRTP == "" {
			p.SRTP = "disabled"
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
	if c.RingTimeout == 0 {
		c.RingTimeout = Duration(60 * time.Second)
	}
	if c.RegisterExpires == 0 {
		c.RegisterExpires = Duration(3600 * time.Second)
	}
	if c.SessionExpires == 0 {
		c.SessionExpires = Duration(1800 * time.Second)
	}
	if c.MinSE == 0 {
		c.MinSE = Duration(90 * time.Second)
	}
	if c.PeerCooldown == 0 {
		c.PeerCooldown = Duration(30 * time.Second)
	}
	if c.SRVCacheTTL == 0 {
		c.SRVCacheTTL = Duration(300 * time.Second)
	}
}
