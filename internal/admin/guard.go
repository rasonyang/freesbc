package admin

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/freesbc/freesbc/internal/config"
)

// hostPolicy decides which Host header values the admin server serves. It
// closes DNS rebinding independent of the auth scheme: a page on another
// origin rebound to the admin address still sends its own host name, which
// is not in the set. It is built once from the startup admin section.
type hostPolicy struct {
	port    string
	defPort bool                // the listen port is the scheme default, so a bare host is accepted
	names   map[string]struct{} // canonical hosts accepted with the listen port
	anyIP   bool                // wildcard listen: any IP literal is accepted
}

// newHostPolicy builds the policy for listen (IP:port), the allowed_hosts
// list and whether the listener serves TLS.
func newHostPolicy(listen string, allowed []string, tls bool) *hostPolicy {
	p := &hostPolicy{names: make(map[string]struct{})}
	ap, err := netip.ParseAddrPort(listen)
	if err != nil {
		return p // validation rejects this; accept nothing rather than guess
	}
	p.port = strconv.Itoa(int(ap.Port()))
	if tls {
		p.defPort = ap.Port() == 443
	} else {
		p.defPort = ap.Port() == 80
	}
	addr := ap.Addr().Unmap()
	switch {
	case addr.IsUnspecified():
		// A wildcard listen has no single address to match. Any IP literal
		// is accepted: a DNS-rebinding page names a host, never an IP
		// literal, because an IP literal cannot be rebound. Names still
		// need allowed_hosts.
		p.anyIP = true
	default:
		p.names[addr.String()] = struct{}{}
	}
	if addr.IsLoopback() {
		for _, n := range []string{"localhost", "127.0.0.1", "::1"} {
			p.names[n] = struct{}{}
		}
	}
	for _, h := range allowed {
		p.names[config.CanonicalHost(h)] = struct{}{}
	}
	return p
}

// allows reports whether the Host header value is acceptable.
func (p *hostPolicy) allows(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port (or an unbracketed IPv6 literal without one).
		host, port = strings.Trim(hostport, "[]"), ""
	}
	if host == "" {
		return false
	}
	if port == "" {
		if !p.defPort {
			return false
		}
	} else if port != p.port {
		return false
	}
	host = config.CanonicalHost(host)
	if _, ok := p.names[host]; ok {
		return true
	}
	if p.anyIP {
		if _, err := netip.ParseAddr(host); err == nil {
			return true
		}
	}
	return false
}

// originAllowed applies the cross-site check to a state-changing request:
// Origin must be exactly this request's own origin; with no Origin header,
// Sec-Fetch-Site must say same-origin. Anything else, including "null", is
// refused.
func originAllowed(r *http.Request, tls bool) bool {
	if o := r.Header.Get("Origin"); o != "" {
		scheme := "http"
		if tls {
			scheme = "https"
		}
		return strings.EqualFold(o, scheme+"://"+r.Host)
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

// guardMW runs the Host and Origin checks before any auth work (no bcrypt,
// no limiter slot). /healthz is exempt from both: load balancers probe it
// by arbitrary names and it returns a constant.
func (s *Server) guardMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if !s.hosts.allows(r.Host) {
			http.Error(w, "misdirected request: unrecognised Host", http.StatusMisdirectedRequest)
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if !originAllowed(r, s.useTLS()) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
