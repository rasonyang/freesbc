package sdp

import (
	"strconv"
	"strings"
)

// canonicalFMTPRef is canonicalFMTP as it was before issue #173, kept
// verbatim as the reference the allocation-free version must match for
// every input (TestCanonicalFMTPMatchesReference and the Build fuzz
// targets). It shares fmtpAllow and the per-parameter validators, which
// the rewrite did not change except fmtpInt's return of an already
// canonical value (canonical either way).

func canonicalFMTPRef(name, raw string) string {
	if raw == "" || len(raw) > maxFMTP {
		return ""
	}
	name = strings.ToLower(name)
	if name == "telephone-event" {
		return canonicalEventsRef(raw)
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

func canonicalEventsRef(raw string) string {
	for _, seg := range strings.Split(raw, ";") {
		if ev, ok := parseEventListRef(strings.TrimSpace(seg)); ok {
			return ev
		}
	}
	return ""
}

func parseEventListRef(v string) (string, bool) {
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

// fmtpIntRef is fmtpInt's original value rendering.
func fmtpIntRef(lo, hi uint64) fmtpParam {
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
