package config

import (
	"fmt"
	"os"
	"regexp"

	"github.com/goccy/go-yaml"
)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse expands ${ENV_VAR} references, strictly unmarshals the YAML
// (unknown keys are errors, reported with line numbers), applies defaults,
// and validates. Secrets are expanded into memory only — callers must never
// write the expanded form back to disk.
func Parse(data []byte) (*Config, error) {
	expanded, err := expandEnv(data)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalWithOptions(expanded, &c, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("parse config:\n%s", yaml.FormatError(err, false, true))
	}
	withDefaults(&c)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config:\n%w", err)
	}
	return &c, nil
}

// expandEnv replaces every ${VAR} with the environment value; any reference
// to an unset variable is an error (silent empty strings hide typos).
func expandEnv(data []byte) ([]byte, error) {
	var missing []string
	out := envRef.ReplaceAllFunc(data, func(m []byte) []byte {
		name := string(envRef.FindSubmatch(m)[1])
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return m
		}
		return []byte(v)
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("undefined environment variable(s) referenced in config: %v", missing)
	}
	return out, nil
}
