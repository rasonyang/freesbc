package sip

import (
	"bytes"
	"hash/fnv"
	"strings"
)

// RegisterHead is what ScanRegister reads off the raw header block of a
// REGISTER request, before (or without) sipgo's parser. Every field is
// empty when its header is absent or malformed.
type RegisterHead struct {
	// Branch is the branch parameter of the topmost Via.
	Branch string
	// CallID is the Call-ID value.
	CallID string
	// AOR is the To address-of-record, normalized as NormalizeAOR does;
	// "" when the To header is missing or malformed.
	AOR string
	// Auth reports whether the request carries an Authorization or
	// Proxy-Authorization header; User, Nonce and AuthKey describe the
	// first one (see DigestIdentity). User is the digest username as sent,
	// never the response or a hash.
	Auth    bool
	User    string
	Nonce   string
	AuthKey uint64
}

var registerPrefix = []byte("REGISTER ")

// ScanRegister reads a REGISTER request's header block from raw bytes: a
// whole UDP datagram or WebSocket message, or a stream message's head. It
// reports false for anything that is not a REGISTER request line. It never
// fails on malformed input: a header it cannot read is left empty. It
// allocates only the strings it returns.
//
// Header names are matched case-insensitively, compact forms (v, i, t)
// included, and folded continuation lines are joined to their header.
func ScanRegister(msg []byte) (RegisterHead, bool) {
	var h RegisterHead
	if !bytes.HasPrefix(msg, registerPrefix) {
		return h, false
	}
	// Skip the request line.
	i := bytes.IndexByte(msg, '\n')
	if i < 0 {
		return h, true
	}
	rest := msg[i+1:]
	var (
		name  []byte
		value []byte // the current header's value, folded lines joined
		via   = false
	)
	flush := func() {
		if name == nil {
			return
		}
		v := strings.TrimSpace(string(value))
		switch {
		case headerIs(name, "via", "v"):
			if !via {
				via = true
				first, _, _ := strings.Cut(v, ",")
				h.Branch, _ = paramOf(first, "branch")
			}
		case headerIs(name, "call-id", "i"):
			if h.CallID == "" {
				h.CallID = v
			}
		case headerIs(name, "to", "t"):
			if h.AOR == "" {
				h.AOR = aorOfToValue(v)
			}
		case headerIs(name, "authorization", "") || headerIs(name, "proxy-authorization", ""):
			if !h.Auth {
				h.Auth = true
				h.User, h.Nonce, h.AuthKey = DigestIdentity(v)
			}
		}
		name, value = nil, nil
	}
	for len(rest) > 0 {
		var line []byte
		if j := bytes.IndexByte(rest, '\n'); j >= 0 {
			line, rest = rest[:j], rest[j+1:]
		} else {
			line, rest = rest, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			break // end of the header block
		}
		if line[0] == ' ' || line[0] == '\t' {
			if name != nil && interesting(name) {
				value = append(append(value, ' '), bytes.TrimSpace(line)...)
			}
			continue
		}
		flush()
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name = bytes.TrimSpace(line[:colon])
		if interesting(name) {
			value = append([]byte(nil), line[colon+1:]...)
		}
	}
	flush()
	return h, true
}

// interesting reports whether ScanRegister reads a header's value.
func interesting(name []byte) bool {
	return headerIs(name, "via", "v") || headerIs(name, "call-id", "i") ||
		headerIs(name, "to", "t") || headerIs(name, "authorization", "") ||
		headerIs(name, "proxy-authorization", "")
}

func headerIs(name []byte, long, compact string) bool {
	return bytes.EqualFold(name, []byte(long)) || (compact != "" && bytes.EqualFold(name, []byte(compact)))
}

// paramOf returns the value of the ;-separated parameter name (case-
// insensitive) of a header value such as a Via.
func paramOf(v, name string) (string, bool) {
	_, params, ok := strings.Cut(v, ";")
	if !ok {
		return "", false
	}
	for p := range strings.SplitSeq(params, ";") {
		k, val, _ := strings.Cut(p, "=")
		if strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(val), true
		}
	}
	return "", false
}

// aorOfToValue reads the AoR out of a raw To header value
// (`"Name" <sip:user@host;p>;tag=x` or `sip:user@host;tag=x`).
func aorOfToValue(v string) string {
	if lt := strings.IndexByte(v, '<'); lt >= 0 {
		gt := strings.IndexByte(v[lt:], '>')
		if gt < 0 {
			return ""
		}
		v = v[lt+1 : lt+gt]
	} else if semi := strings.IndexByte(v, ';'); semi >= 0 {
		v = v[:semi]
	}
	v = strings.TrimSpace(v)
	scheme, rest, ok := strings.Cut(v, ":")
	if !ok || !(strings.EqualFold(scheme, "sip") || strings.EqualFold(scheme, "sips")) {
		return ""
	}
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return ""
	}
	user, host := rest[:at], rest[at+1:]
	if c := strings.IndexByte(user, ':'); c >= 0 {
		user = user[:c] // user:password
	}
	if end := strings.IndexAny(host, ";?"); end >= 0 {
		host = host[:end]
	}
	if strings.HasPrefix(host, "[") {
		if rb := strings.IndexByte(host, ']'); rb >= 0 {
			host = host[:rb+1]
		}
	} else if c := strings.IndexByte(host, ':'); c >= 0 {
		host = host[:c]
	}
	aor, ok := NormalizeAOR(user, host)
	if !ok {
		return ""
	}
	return aor
}

// NormalizeAOR builds the address-of-record "user@host", lower-cased, from
// a To URI's user and host. It reports false for an empty part, a part
// carrying a structural character, or an over-long part: a user part is
// copied into a Request-URI and a log line, so anything structural in it is
// malformed, not merely unusual.
func NormalizeAOR(user, host string) (string, bool) {
	if user == "" || host == "" {
		return "", false
	}
	if strings.ContainsAny(user, "@ \t\r\n<>;,\"") || len(user) > 128 {
		return "", false
	}
	if strings.ContainsAny(host, " \t\r\n<>;,\"") || len(host) > 255 {
		return "", false
	}
	return strings.ToLower(user + "@" + host), true
}

// DigestParam returns the value of one auth-param (case-insensitive name,
// quotes removed) of an Authorization, Proxy-Authorization,
// WWW-Authenticate or Proxy-Authenticate value ("Digest k=v, k=\"v\"").
func DigestParam(value, name string) (string, bool) {
	var out string
	found := false
	eachDigestParam(value, func(k, v string) bool {
		if strings.EqualFold(k, name) {
			out, found = v, true
			return false
		}
		return true
	})
	return out, found
}

// DigestIdentity identifies one credential attempt: its username as sent
// ("" when absent), its nonce, and a 64-bit
// FNV-1a key over the fields that make it a distinct attempt (username,
// realm, nonce, uri, response, cnonce, nc). The same attempt read from raw
// bytes and from a parsed header yields the same key, whatever the spacing
// and quoting. A value without a response is keyed by its trimmed text.
func DigestIdentity(value string) (user, nonce string, key uint64) {
	fields := [...]string{"username", "realm", "nonce", "uri", "response", "cnonce", "nc"}
	var vals [len(fields)]string
	eachDigestParam(value, func(k, v string) bool {
		for i, f := range fields {
			if strings.EqualFold(k, f) && vals[i] == "" {
				vals[i] = v
			}
		}
		return true
	})
	f := fnv.New64a()
	if vals[4] == "" {
		_, _ = f.Write([]byte(strings.TrimSpace(value)))
		return vals[0], vals[2], f.Sum64()
	}
	for _, v := range vals {
		_, _ = f.Write([]byte(v))
		_, _ = f.Write([]byte{0})
	}
	return vals[0], vals[2], f.Sum64()
}

// eachDigestParam calls fn for each k=v auth-param of a challenge or
// credentials value, after the scheme token, until fn returns false.
// Quoted values may contain commas and escaped quotes.
func eachDigestParam(value string, fn func(k, v string) bool) {
	s := strings.TrimSpace(value)
	// The scheme ("Digest") is the first token, unless the value starts
	// with a parameter.
	if sp := strings.IndexAny(s, " \t"); sp >= 0 && !strings.Contains(s[:sp], "=") {
		s = s[sp+1:]
	}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t,")
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return
		}
		k := strings.TrimSpace(s[:eq])
		s = strings.TrimLeft(s[eq+1:], " \t")
		var v string
		if strings.HasPrefix(s, `"`) {
			var b strings.Builder
			i := 1
			for ; i < len(s); i++ {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					i++
					b.WriteByte(s[i])
					continue
				}
				if c == '"' {
					break
				}
				b.WriteByte(c)
			}
			v = b.String()
			if i < len(s) {
				i++ // the closing quote
			}
			s = s[i:]
			if c := strings.IndexByte(s, ','); c >= 0 {
				s = s[c+1:]
			} else {
				s = ""
			}
		} else if c := strings.IndexByte(s, ','); c >= 0 {
			v, s = strings.TrimSpace(s[:c]), s[c+1:]
		} else {
			v, s = strings.TrimSpace(s), ""
		}
		if !fn(k, v) {
			return
		}
	}
}
