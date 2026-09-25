package config

import (
	"reflect"
	"sort"
)

// restartOnly lists the settings a running process reads once, at startup,
// and never again: the listener set, the edge topology, the certificates
// loaded at bind and the existence of each plane. Each entry names the
// config keys it covers and extracts a comparable value from a snapshot.
// docs/design.md §4.4 "What is hot vs restart-only" is the same table in
// prose; keep the two in step.
var restartOnly = []struct {
	key string
	get func(*Config) any
}{
	// Plane existence: app.Run decides once which planes run.
	{"peers (trunk plane on/off)", func(c *Config) any { return len(c.Peers) > 0 }},
	{"sip.upstream / sip.upstreams.nodes (edge plane on/off)", func(c *Config) any { return c.ProxyEnabled() }},
	{"admin (section present)", func(c *Config) any { return c.Admin != nil }},

	// Trunk: the bound listener set, the port it advertises and the
	// certificates loaded at bind or at Run.
	{"listen.sip / sip.bind_ip / sip.bind_port / sip.transport", func(c *Config) any { return c.Listeners() }},
	{"sip.advertised_port", func(c *Config) any { return c.SIP.AdvertisedPort }},
	{"listen.tls_cert / listen.tls_key / listen.tls_client_ca", func(c *Config) any {
		return [3]string{c.Listen.TLSCert, c.Listen.TLSKey, c.Listen.TLSClientCA}
	}},
	{"peers.*.tls_ca / tls_client_cert / tls_client_key", func(c *Config) any {
		m := map[string][3]string{}
		for name, p := range c.Peers {
			if p != nil && (p.TLSCA != "" || p.TLSClientCert != "" || p.TLSClientKey != "") {
				m[name] = [3]string{p.TLSCA, p.TLSClientCert, p.TLSClientKey}
			}
		}
		return m
	}},

	// Edge: listeners, topology and media planes (buildTopology and
	// newMediaPools read them once, in edge.New).
	{"sip.public", func(c *Config) any { return c.SIP.Public }},
	{"sip.private", func(c *Config) any { return c.SIP.Private }},
	{"network", func(c *Config) any { return c.Network }},
	{"sip.upstream / sip.upstreams.nodes / sip.upstreams.algorithm", func(c *Config) any {
		return [3]any{c.SIP.Upstream, c.SIP.Upstreams.Nodes, c.SIP.Upstreams.Algorithm}
	}},
	{"sip.pstn (address, transport, match, gateways, routes)", func(c *Config) any {
		p := c.SIP.Pstn
		routes := make([][2]any, 0, len(p.Routes))
		for _, r := range p.Routes {
			if r != nil {
				routes = append(routes, [2]any{r.Match, r.To})
			}
		}
		return [5]any{p.Address, p.Transport, p.Match, p.Gateways, routes}
	}},
	{"rtp.public / rtp.private", func(c *Config) any { return [2]RTPPlaneConfig{c.RTP.Public, c.RTP.Private} }},
	{"webrtc", func(c *Config) any { return c.WebRTC }},

	// Admin: the HTTP listener and its certificate.
	{"admin.listen / admin.allow_remote / admin.tls_cert / admin.tls_key", func(c *Config) any {
		if c.Admin == nil {
			return nil
		}
		return [4]any{c.Admin.Listen, c.Admin.AllowRemote, c.Admin.TLSCert, c.Admin.TLSKey}
	}},
}

// RestartOnlyChanges reports which restart-only settings differ between the
// snapshot the process started with and next, as the config keys an
// operator would edit, sorted. An empty result means next changes only hot
// settings.
//
// A reload that changes a restart-only setting is still published — its
// hot settings apply at once — but the running planes keep acting on their
// startup values until the process restarts; config.Watch logs this list
// so the operator knows the file and the process now disagree.
func RestartOnlyChanges(running, next *Config) []string {
	var out []string
	for _, f := range restartOnly {
		if !reflect.DeepEqual(f.get(running), f.get(next)) {
			out = append(out, f.key)
		}
	}
	sort.Strings(out)
	return out
}
