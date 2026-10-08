// Package config loads, validates, and hot-reloads the freesbc.yaml
// configuration file — the single source of truth for FreeSBC.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// yamlScalarString decodes one YAML scalar node to its string value,
// handling quoting and escapes; UnmarshalYAML receives raw node bytes
// which include any quote characters the user wrote.
func yamlScalarString(b []byte) (string, error) {
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// Duration parses YAML scalars like "60s" or "1h" via time.ParseDuration.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(b []byte) error {
	s, err := yamlScalarString(b)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", string(b), err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// PortRange is an inclusive UDP port range, written as "16384-32768".
type PortRange struct {
	Min, Max uint16
}

// Pairs is how many RTP/RTCP pairs fit in the range: RTP on an even port,
// RTCP on RTP+1 (media.PlanePool.sweep).
func (p PortRange) Pairs() int {
	lo, hi := int(p.Min), int(p.Max)
	if lo%2 != 0 {
		lo++
	}
	if hi < lo {
		return 0
	}
	return (hi - lo + 1) / 2
}

func (p *PortRange) UnmarshalYAML(b []byte) error {
	s, err := yamlScalarString(b)
	if err != nil {
		return fmt.Errorf("invalid port range %q: %w", string(b), err)
	}
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return fmt.Errorf("invalid port range %q: want \"min-max\"", s)
	}
	minP, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port range %q: %w", s, err)
	}
	maxP, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port range %q: %w", s, err)
	}
	if minP == 0 || minP >= maxP {
		return fmt.Errorf("invalid port range %q: min must be >0 and < max", s)
	}
	p.Min, p.Max = uint16(minP), uint16(maxP)
	return nil
}

// RateLimit is the parsed form of a shield rate limit, e.g. "20/s per_ip".
type RateLimit struct {
	Rate     int
	Interval time.Duration
	PerIP    bool
}

// ParseRateLimit parses "<n>/<s|m|h>[ per_ip]".
func ParseRateLimit(s string) (RateLimit, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 || len(fields) > 2 {
		return RateLimit{}, fmt.Errorf("invalid rate limit %q: want \"<n>/<s|m|h> [per_ip]\"", s)
	}
	var rl RateLimit
	if len(fields) == 2 {
		if fields[1] != "per_ip" {
			return RateLimit{}, fmt.Errorf("invalid rate limit %q: unknown scope %q", s, fields[1])
		}
		rl.PerIP = true
	}
	numStr, unit, ok := strings.Cut(fields[0], "/")
	if !ok {
		return RateLimit{}, fmt.Errorf("invalid rate limit %q: missing \"/\"", s)
	}
	n, err := strconv.Atoi(numStr)
	if err != nil || n <= 0 {
		return RateLimit{}, fmt.Errorf("invalid rate limit %q: rate must be a positive integer", s)
	}
	rl.Rate = n
	switch unit {
	case "s":
		rl.Interval = time.Second
	case "m":
		rl.Interval = time.Minute
	case "h":
		rl.Interval = time.Hour
	default:
		return RateLimit{}, fmt.Errorf("invalid rate limit %q: unit must be s, m, or h", s)
	}
	return rl, nil
}
