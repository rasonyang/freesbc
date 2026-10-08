package config

import (
	"reflect"
	"sort"
)

// restartOnly lists the settings a running process reads once, at startup,
// and never again: addresses, listener sets, the edge topology, the
// certificates loaded at bind and the admin listener. Every top-level
// section is restart-only except shield. Each entry names the config keys
// it covers and extracts a comparable value from a snapshot.
// docs/design.md §4.4 "What is hot vs restart-only" is the same table in
// prose; keep the two in step.
var restartOnly = []struct {
	key string
	get func(*Config) any
}{
	{"public", func(c *Config) any { return c.Public }},
	{"private", func(c *Config) any { return c.Private }},
	{"rtp", func(c *Config) any { return c.RTP }},
	{"tls", func(c *Config) any { return c.TLS }},
	{"edge.switch", func(c *Config) any { return c.Edge.Switch }},
	{"edge.switch_carrier_port", func(c *Config) any { return c.Edge.SwitchCarrierPort }},
	{"edge.listen", func(c *Config) any { return c.Edge.Listen }},
	{"edge.carriers", func(c *Config) any { return c.Edge.Carriers }},
	{"edge.srtp", func(c *Config) any { return c.Edge.SRTP }},
	{"edge.allow_insecure_sdes", func(c *Config) any { return c.Edge.AllowInsecureSDES }},
	{"edge.carrier_sources", func(c *Config) any { return c.Edge.CarrierSources }},
	{"admin", func(c *Config) any { return c.Admin }},
}

// RestartOnlyChanges reports which restart-only settings differ between the
// snapshot the process started with and next, as the config keys an
// operator would edit, sorted. An empty result means next changes only hot
// settings (shield).
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
