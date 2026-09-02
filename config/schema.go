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
	// MaxConcurrentCalls caps total in-flight bridged calls across every
	// peer (0 = unlimited, the default). Enforced by bridge.onInvite's T-06
	// quota gate; a per-peer cap lives on Peer.
	MaxConcurrentCalls int `yaml:"max_concurrent_calls"`

	// SIP and RTP configure the bind/advertised address topology for NAT/VPN
	// deployments: the SBC sits behind a NAT/VPN with a private bind address
	// and a public advertised one, and the two must stay independent.
	//
	// When sip.bind_ip is set, the sip section REPLACES listen.sip
	// (validation rejects configuring both): the SBC binds exactly one
	// listener at sip.bind_ip:sip.bind_port and advertises
	// sip.advertised_ip:sip.advertised_port in Contact/From/REGISTER. When
	// unset, the legacy listen.sip + listen.media.public_ip resolution
	// applies (see Server.sigIP). The rtp section likewise overrides just
	// the media plane: every RTP/RTCP socket binds to rtp.bind_ip (empty =
	// every interface, see media.Pool), and SDP c=/o= advertises
	// rtp.advertised_ip (empty = legacy resolution, see Server.mediaIP).
	SIP SIPNetConfig `yaml:"sip"`
	RTP RTPNetConfig `yaml:"rtp"`
}

type ListenConfig struct {
	SIP   []SIPListen `yaml:"sip"`
	Media MediaConfig `yaml:"media"`
	// TLSCert/TLSKey are the inbound TLS identity for tls:// SIP listeners
	// (T-17/F-13): with them set, listeners present this certificate and
	// verification is possible against a real trust anchor — instead of the
	// default fresh self-signed certificate (kept when unset, with a
	// startup warning). TLSClientCA turns inbound TLS into mutual TLS:
	// clients must present a certificate chaining to this CA.
	TLSCert     string `yaml:"tls_cert"`
	TLSKey      string `yaml:"tls_key"`
	TLSClientCA string `yaml:"tls_client_ca"`
}

type MediaConfig struct {
	PortRange  PortRange `yaml:"port_range"`
	PublicIP   string    `yaml:"public_ip"`   // "auto" (STUN-detected) or a literal IP
	RTPTimeout Duration  `yaml:"rtp_timeout"` // tear down a call after this much RTP silence
}

// SIPNetConfig is the signaling-plane bind/advertised pair (see Config.SIP).
type SIPNetConfig struct {
	// BindIP/BindPort are where the SIP listener actually binds. When
	// BindIP is set the section replaces listen.sip (see Config.Listeners).
	BindIP   string `yaml:"bind_ip"`
	BindPort int    `yaml:"bind_port"`
	// Transport of the listener: udp (default), tcp, or tls.
	Transport string `yaml:"transport"`
	// AdvertisedIP/AdvertisedPort are what externally visible signaling
	// (Contact, From, REGISTER Contact) claims; the far side must be able
	// to route to it. Default to the bind values when unset.
	AdvertisedIP   string `yaml:"advertised_ip"`
	AdvertisedPort int    `yaml:"advertised_port"`
}

// RTPNetConfig is the media-plane bind/advertised pair plus the explicit
// port range (see Config.RTP).
type RTPNetConfig struct {
	// BindIP is the local address every RTP/RTCP socket binds to; empty
	// (the default) binds every interface.
	BindIP string `yaml:"bind_ip"`
	// AdvertisedIP is the address written into SDP c=/o=; empty falls back
	// to the legacy listen.media.public_ip resolution.
	AdvertisedIP string `yaml:"advertised_ip"`
	// PortMin/PortMax bound the RTP/RTCP port range when set (both or
	// neither). They REPLACE listen.media.port_range (validation rejects
	// configuring both) — see Config.RTPPortRange.
	PortMin int `yaml:"port_min"`
	PortMax int `yaml:"port_max"`
}

// Listeners returns the effective SIP listener set: the sip.bind_ip
// topology when configured, else listen.sip. Only meaningful on a
// validated Config (validate rejects configuring both).
func (c *Config) Listeners() []SIPListen {
	if c.SIP.BindIP != "" {
		return []SIPListen{{Transport: c.SIP.Transport, Host: c.SIP.BindIP, Port: c.SIP.BindPort}}
	}
	return c.Listen.SIP
}

// RTPPortRange returns the configured RTP port range: rtp.port_min/port_max
// when set, else listen.media.port_range. Only meaningful on a validated
// Config (validate rejects configuring both).
func (c *Config) RTPPortRange() PortRange {
	if c.RTP.PortMin != 0 {
		return PortRange{Min: uint16(c.RTP.PortMin), Max: uint16(c.RTP.PortMax)}
	}
	return c.Listen.Media.PortRange
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
	// MaxConcurrentCalls caps how many bridged calls this peer may have in
	// flight at once (0 = unlimited, the default). Enforced by
	// bridge.onInvite's T-06 quota gate.
	MaxConcurrentCalls int `yaml:"max_concurrent_calls"`
	// TLSCA is the outbound trust anchor for dialing this peer over tls
	// (T-17/F-13): a PEM CA bundle ADDED to the system roots, so a carrier
	// with a private/self-signed CA is reachable without disabling
	// verification. TLSClientCert/TLSClientKey present OUR client
	// certificate when the carrier requires mutual TLS (both-or-neither).
	// Changes take effect on restart (no hot rotation).
	TLSCA         string `yaml:"tls_ca"`
	TLSClientCert string `yaml:"tls_client_cert"`
	TLSClientKey  string `yaml:"tls_client_key"`

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
	// Realm pins the digest realm we will answer a challenge FOR
	// (T-19/F-20): when set, a 401/407 whose WWW-/Proxy-Authenticate
	// names any other realm is treated as an auth failure — the SBC never
	// computes a digest of its credentials for it, so a rogue or
	// compromised server can't harvest responses for offline cracking.
	// Empty = accept whatever realm the far end names (pre-T-19 behavior).
	Realm string `yaml:"realm"`
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
	RateLimit string `yaml:"rate_limit"`
	// PeerRateLimit is the looser per-IP limit applied to CONFIGURED peer
	// sources (T-18/F-19): peers are exempt from the ban/scanner plane but
	// not from rate limiting, so a spoofed peer source still has a ceiling.
	PeerRateLimit string  `yaml:"peer_rate_limit"`
	AutoBan       AutoBan `yaml:"auto_ban"`
	NFTables      string  `yaml:"nftables"` // auto, on, off
}

type AutoBan struct {
	Failures int      `yaml:"failures"`
	Window   Duration `yaml:"window"`
	Duration Duration `yaml:"duration"`
}

type AdminConfig struct {
	Listen string    `yaml:"listen"`
	Auth   AdminAuth `yaml:"auth"`
	// AllowRemote permits a NON-loopback listen address (T-26/D4-6). By
	// default the admin API — plaintext Basic auth in front of the FULL
	// config including every peer credential — must stay loopback-only;
	// binding it wider is a conscious, flagged decision, not a typo.
	// Prefer TLS (tls_cert/tls_key) or a reverse proxy when doing so.
	AllowRemote bool `yaml:"allow_remote"`
	// TLSCert/TLSKey (T-26b, extends the reviewed plan): when both are set,
	// the admin listener serves HTTPS with this certificate (TLS >= 1.2),
	// so a non-loopback (LAN) deployment doesn't send Basic credentials in
	// the clear. Both-or-neither; a change takes effect on restart (no hot
	// rotation).
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
}

type AdminAuth struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// withDefaults fills spec-defined defaults on a freshly parsed Config.
func withDefaults(c *Config) {
	// The default range only applies when NEITHER range source is set: with
	// rtp.port_min/port_max configured, the legacy range must stay zero so
	// validate's mutual-exclusion check (and RTPPortRange) can tell the two
	// sources apart.
	if c.Listen.Media.PortRange == (PortRange{}) && c.RTP.PortMin == 0 && c.RTP.PortMax == 0 {
		c.Listen.Media.PortRange = PortRange{Min: 16384, Max: 32768}
	}
	if c.Listen.Media.PublicIP == "" {
		c.Listen.Media.PublicIP = "auto"
	}
	if c.Listen.Media.RTPTimeout == 0 {
		c.Listen.Media.RTPTimeout = Duration(5 * time.Minute)
	}
	if c.SIP.Transport == "" {
		c.SIP.Transport = "udp"
	}
	if c.SIP.BindIP != "" && c.SIP.AdvertisedIP == "" {
		c.SIP.AdvertisedIP = c.SIP.BindIP
	}
	if c.SIP.BindPort != 0 && c.SIP.AdvertisedPort == 0 {
		c.SIP.AdvertisedPort = c.SIP.BindPort
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
	if c.Shield.PeerRateLimit == "" {
		c.Shield.PeerRateLimit = "200/s per_ip"
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
