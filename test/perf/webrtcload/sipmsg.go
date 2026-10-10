package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// sipMsg is the little this client needs from a SIP message.
type sipMsg struct {
	status int    // response status code, 0 for a request
	method string // request method
	hdr    map[string][]string
	body   string
}

func parseSIP(raw []byte) (*sipMsg, error) {
	s := string(raw)
	head, body, _ := strings.Cut(s, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("empty SIP message")
	}
	m := &sipMsg{hdr: map[string][]string{}, body: body}
	first := strings.Fields(lines[0])
	if len(first) >= 2 && strings.HasPrefix(first[0], "SIP/2.0") {
		code, err := strconv.Atoi(first[1])
		if err != nil {
			return nil, fmt.Errorf("bad status line %q", lines[0])
		}
		m.status = code
	} else if len(first) >= 1 {
		m.method = first[0]
	}
	// Unfold continuation lines.
	var cur string
	flush := func() {
		if cur == "" {
			return
		}
		k, v, ok := strings.Cut(cur, ":")
		if ok {
			k = strings.ToLower(strings.TrimSpace(k))
			if long, ok := compact[k]; ok {
				k = long
			}
			m.hdr[k] = append(m.hdr[k], strings.TrimSpace(v))
		}
		cur = ""
	}
	for _, l := range lines[1:] {
		if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") {
			cur += " " + strings.TrimSpace(l)
			continue
		}
		flush()
		cur = l
	}
	flush()
	return m, nil
}

var compact = map[string]string{"i": "call-id", "f": "from", "t": "to", "v": "via", "m": "contact", "l": "content-length", "c": "content-type"}

func (m *sipMsg) first(k string) string {
	if v := m.hdr[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (m *sipMsg) callID() string { return m.first("call-id") }

func (m *sipMsg) cseqMethod() string {
	f := strings.Fields(m.first("cseq"))
	if len(f) == 2 {
		return strings.ToUpper(f[1])
	}
	return ""
}

// toTag is the tag parameter of the To header.
func (m *sipMsg) toTag() string { return headerParam(m.first("to"), "tag") }

func headerParam(h, name string) string {
	for _, p := range strings.Split(h, ";")[1:] {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// contactURI is the URI inside the first Contact header.
func (m *sipMsg) contactURI() string {
	c := m.first("contact")
	if i := strings.Index(c, "<"); i >= 0 {
		if j := strings.Index(c[i:], ">"); j > 0 {
			return c[i+1 : i+j]
		}
	}
	u, _, _ := strings.Cut(c, ";")
	return strings.TrimSpace(u)
}

// routeSet is the dialog route set a UAC builds from a response: the
// Record-Route URIs in reverse order.
func (m *sipMsg) routeSet() []string {
	var all []string
	for _, h := range m.hdr["record-route"] {
		for _, p := range splitRoutes(h) {
			all = append(all, p)
		}
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all
}

// splitRoutes splits a comma-separated Route/Record-Route value on the commas
// outside angle brackets.
func splitRoutes(h string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range h {
		switch r {
		case '<':
			depth++
		case '>':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(h[start:i]))
				start = i + 1
			}
		}
	}
	if t := strings.TrimSpace(h[start:]); t != "" {
		out = append(out, t)
	}
	return out
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// digest answers a WWW-/Proxy-Authenticate challenge (MD5, qop=auth or none).
type digestChallenge struct {
	realm, nonce, opaque, qop, algorithm string
}

func parseChallenge(h string) (digestChallenge, bool) {
	h = strings.TrimSpace(h)
	if len(h) < 7 || !strings.EqualFold(h[:6], "digest") {
		return digestChallenge{}, false
	}
	var c digestChallenge
	for _, kv := range splitParams(h[6:]) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "realm":
			c.realm = v
		case "nonce":
			c.nonce = v
		case "opaque":
			c.opaque = v
		case "qop":
			c.qop = v
		case "algorithm":
			c.algorithm = v
		}
	}
	return c, c.nonce != ""
}

func splitParams(s string) []string {
	var out []string
	inQ, start := false, 0
	for i, r := range s {
		switch r {
		case '"':
			inQ = !inQ
		case ',':
			if !inQ {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// authorization is the credentials header value answering c.
func (c digestChallenge) authorization(user, pass, method, uri string, nc int) string {
	ha1 := md5hex(user + ":" + c.realm + ":" + pass)
	ha2 := md5hex(method + ":" + uri)
	h := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s"`, user, c.realm, c.nonce, uri)
	if strings.Contains(c.qop, "auth") {
		cnonce := randToken(8)
		ncs := fmt.Sprintf("%08x", nc)
		resp := md5hex(ha1 + ":" + c.nonce + ":" + ncs + ":" + cnonce + ":auth:" + ha2)
		h += fmt.Sprintf(`, response="%s", cnonce="%s", nc=%s, qop=auth`, resp, cnonce, ncs)
	} else {
		h += fmt.Sprintf(`, response="%s"`, md5hex(ha1+":"+c.nonce+":"+ha2))
	}
	if c.opaque != "" {
		h += fmt.Sprintf(`, opaque="%s"`, c.opaque)
	}
	h += ", algorithm=MD5"
	return h
}
