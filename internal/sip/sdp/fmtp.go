package sdp

import (
	"strconv"
	"strings"
)

// fmtp handling.
//
// An a=fmtp value is free text written by the other leg. Copying it across
// verbatim would let that leg put anything into the body the proxy builds
// for the far side — an address, a port, or a bare CR that a lenient
// parser treats as a line break and so as a new SDP line. That breaks the
// from-scratch rule every emitted body follows.
//
// So fmtp is never copied: it is PARSED against a per-codec allowlist of
// parameters, each with a typed value, and RE-RENDERED canonically as
// "name=value;name=value" (telephone-event: its event list). A parameter
// not on the list, a value that does not fit its type, and every codec
// without an entry lose their fmtp entirely. Dropping an fmtp parameter is
// always safe for a codec the proxy relays without transcoding: the far
// side falls back to the codec's defaults, which both ends must support.

// fmtpParam validates one parameter value and returns its canonical form.
type fmtpParam func(v string) (string, bool)

// fmtpInt accepts a decimal integer in [lo, hi].
func fmtpInt(lo, hi uint64) fmtpParam {
	return func(v string) (string, bool) {
		if len(v) == 0 || len(v) > 10 {
			return "", false
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n < lo || n > hi {
			return "", false
		}
		return strconv.FormatUint(n, 10), true
	}
}

// fmtpEnum accepts one of a fixed set of values, case-insensitively, and
// renders it as written in the set.
func fmtpEnum(vals ...string) fmtpParam {
	return func(v string) (string, bool) {
		for _, want := range vals {
			if strings.EqualFold(v, want) {
				return want, true
			}
		}
		return "", false
	}
}

var fmtpBool = fmtpEnum("0", "1")

// fmtpAllow is the per-codec allowlist, keyed by lower-cased encoding name.
// Parameter names are matched case-insensitively and rendered lower-case.
var fmtpAllow = map[string]map[string]fmtpParam{
	// RFC 7587 §6.1.
	"opus": {
		"maxplaybackrate":      fmtpInt(8000, 48000),
		"sprop-maxcapturerate": fmtpInt(8000, 48000),
		"maxptime":             fmtpInt(3, 120),
		"ptime":                fmtpInt(3, 120),
		"minptime":             fmtpInt(3, 120),
		"maxaveragebitrate":    fmtpInt(6000, 510000),
		"stereo":               fmtpBool,
		"sprop-stereo":         fmtpBool,
		"cbr":                  fmtpBool,
		"useinbandfec":         fmtpBool,
		"usedtx":               fmtpBool,
	},
	// RFC 4867 §8.1 (the subset a transcoding-free relay can carry).
	"amr": {
		"octet-align":            fmtpBool,
		"mode-set":               fmtpModeSet(7),
		"mode-change-period":     fmtpEnum("1", "2"),
		"mode-change-capability": fmtpEnum("1", "2"),
		"mode-change-neighbor":   fmtpBool,
		"crc":                    fmtpBool,
		"robust-sorting":         fmtpBool,
		"max-red":                fmtpInt(0, 65535),
	},
	"amr-wb": {
		"octet-align":            fmtpBool,
		"mode-set":               fmtpModeSet(8),
		"mode-change-period":     fmtpEnum("1", "2"),
		"mode-change-capability": fmtpEnum("1", "2"),
		"mode-change-neighbor":   fmtpBool,
		"crc":                    fmtpBool,
		"robust-sorting":         fmtpBool,
		"max-red":                fmtpInt(0, 65535),
	},
	// RFC 4856 §2.1.9.
	"g729": {"annexb": fmtpEnum("yes", "no")},
	// RFC 3952 §5.
	"ilbc": {"mode": fmtpEnum("20", "30")},
	// RFC 5577 §6.1.
	"g7221": {"bitrate": fmtpEnum("24000", "32000", "48000")},
}

// fmtpModeSet accepts an AMR mode-set: a comma-separated list of mode
// numbers 0..max.
func fmtpModeSet(max int) fmtpParam {
	return func(v string) (string, bool) {
		parts := strings.Split(v, ",")
		if len(parts) > max+1 {
			return "", false
		}
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 0 || n > max {
				return "", false
			}
			out = append(out, strconv.Itoa(n))
		}
		return strings.Join(out, ","), true
	}
}

// maxFMTP bounds the raw fmtp value considered at all. Real values are a
// few dozen bytes.
const maxFMTP = 512

// canonicalFMTP returns the allowlisted, canonical form of an fmtp value
// for the named codec, or "" when nothing survives. It is the only way an
// fmtp value enters a Codec parsed by this package and the only form Build
// writes, so the emitted text is always the proxy's own rendering.
func canonicalFMTP(name, raw string) string {
	if raw == "" || len(raw) > maxFMTP {
		return ""
	}
	name = strings.ToLower(name)
	if name == "telephone-event" {
		return canonicalEvents(raw)
	}
	allow, ok := fmtpAllow[name]
	if !ok {
		return ""
	}
	var out []string
	seen := map[string]bool{}
	for _, seg := range strings.Split(raw, ";") {
		k, v, ok := strings.Cut(seg, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		check, ok := allow[k]
		if !ok || seen[k] {
			continue
		}
		cv, ok := check(strings.TrimSpace(v))
		if !ok {
			continue
		}
		seen[k] = true
		out = append(out, k+"="+cv)
	}
	return strings.Join(out, ";")
}

// canonicalEvents extracts an RFC 4733 §7.1.1 event list ("0-15,66,70")
// from a telephone-event fmtp value. Anything that is not an event list
// (some stacks append ";key=value" noise) is dropped.
func canonicalEvents(raw string) string {
	for _, seg := range strings.Split(raw, ";") {
		if ev, ok := parseEventList(strings.TrimSpace(seg)); ok {
			return ev
		}
	}
	return ""
}

func parseEventList(v string) (string, bool) {
	if v == "" {
		return "", false
	}
	parts := strings.Split(v, ",")
	if len(parts) > 64 {
		return "", false
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(p), "-")
		a, ok := eventNumber(lo)
		if !ok {
			return "", false
		}
		if !isRange {
			out = append(out, strconv.Itoa(a))
			continue
		}
		b, ok := eventNumber(hi)
		if !ok || b < a {
			return "", false
		}
		out = append(out, strconv.Itoa(a)+"-"+strconv.Itoa(b))
	}
	return strings.Join(out, ","), true
}

func eventNumber(s string) (int, bool) {
	if len(s) == 0 || len(s) > 3 {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 255 {
		return 0, false
	}
	return n, true
}
