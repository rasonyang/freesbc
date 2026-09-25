package config

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse strictly unmarshals the raw YAML (unknown keys are errors, reported
// with line numbers against the user's own file), rejects null map/list
// entries, then expands ${ENV_VAR} references in the decoded string fields,
// applies defaults, and validates.
//
// Expansion runs after unmarshalling — not on the raw bytes — so that: (a)
// parse errors never echo secret values, only the literal ${VAR} text the
// user wrote; (b) ${VAR} inside YAML comments is inert, since comments don't
// survive unmarshalling; (c) secrets containing quotes or newlines survive
// verbatim, since they're substituted after YAML's own escaping is resolved.
//
// Secrets are expanded into memory only — callers must never write the
// expanded form back to disk.
//
// Parse never panics on any input: a bad file is an error, because the
// reload goroutine (Watch) runs it on whatever an operator saved.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := unmarshalStrict(data, &c); err != nil {
		return nil, err
	}
	if err := rejectNullEntries(&c); err != nil {
		return nil, err
	}
	if err := expandEnv(&c); err != nil {
		return nil, err
	}
	withDefaults(&c)
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config:\n%w", err)
	}
	return &c, nil
}

// unmarshalStrict is the strict YAML step. goccy/go-yaml v1.19.2 panics on
// some malformed tags (a nil dereference in ast.(*ArrayNodeIter).Len, audit
// P3-CORE-001), so a panic from the decoder is turned into a parse error
// instead of taking the process down. The recovered value is not echoed: it
// is an internal decoder message, not something the operator wrote.
func unmarshalStrict(data []byte, c *Config) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parse config: malformed YAML (the decoder failed on this input; check tags such as !foo and indentation)")
		}
	}()
	if uerr := yaml.UnmarshalWithOptions(data, c, yaml.Strict()); uerr != nil {
		return fmt.Errorf("parse config:\n%s", yaml.FormatError(uerr, false, true))
	}
	return nil
}

// rejectNullEntries fails on map values and list items that decoded to nil
// (an empty `name:` block or a `- ~` item). The rest of the lifecycle
// (withDefaults, validate) dereferences these entries, and a null entry is
// always an operator mistake: there is no meaningful "empty peer".
func rejectNullEntries(c *Config) error {
	var errs []string
	nullKeys := func(section string, keys []string) {
		sort.Strings(keys)
		for _, k := range keys {
			errs = append(errs, fmt.Sprintf("%s.%s: empty entry (null); give it its settings or remove it", section, k))
		}
	}
	var peers []string
	for name, p := range c.Peers {
		if p == nil {
			peers = append(peers, name)
		}
	}
	nullKeys("peers", peers)
	for i, r := range c.Routes {
		if r == nil {
			errs = append(errs, fmt.Sprintf("routes[%d]: empty entry (null)", i))
		}
	}
	var nodes []string
	for name, n := range c.SIP.Upstreams.Nodes {
		if n == nil {
			nodes = append(nodes, name)
		}
	}
	nullKeys("sip.upstreams.nodes", nodes)
	var gws []string
	for name, g := range c.SIP.Pstn.Gateways {
		if g == nil {
			gws = append(gws, name)
		}
	}
	nullKeys("sip.pstn.gateways", gws)
	for i, r := range c.SIP.Pstn.Routes {
		if r == nil {
			errs = append(errs, fmt.Sprintf("sip.pstn.routes[%d]: empty entry (null)", i))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n%s", strings.Join(errs, "\n"))
	}
	return nil
}
