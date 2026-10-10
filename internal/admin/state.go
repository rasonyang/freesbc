package admin

import (
	"net/http"
	"strconv"
	"time"
)

// This file serves the read-only live-state tables: client registrations,
// carrier registrations, shield bans, switch nodes and carriers. Each is a
// snapshot closure in Deps over the plain types below; app converts the
// planes' own records into them, so admin never imports edge or shield. No
// type here carries a client token, Call-ID, Contact or credential.

// Registration is one live client binding.
type Registration struct {
	AOR       string
	User      string
	Transport string
	Source    string // transport source "IP:port"
	ExpiresAt time.Time
}

// CarrierRegistration is one live switch-to-carrier registration.
type CarrierRegistration struct {
	Carrier string
	User    string
	Token   string // the opaque fsbc token FreeSBC put in the carrier Contact
	Node    string // switch node "IP:port"
	Expires time.Time
}

// Ban is one live shield ban.
type Ban struct {
	Source string // IP, or IP:port for a UDP socket ban
	Kind   string // "ip" or "udp_socket"
	Reason string // "scanner"
	Since  time.Time
	Until  time.Time
}

// SwitchNode is the passive health of one switch node.
type SwitchNode struct {
	Address           string
	State             string // "healthy" or "cooling_down"
	CooldownRemaining time.Duration
	LastFailure       time.Time // zero if never
}

// CarrierAddress is one resolved carrier destination.
type CarrierAddress struct {
	Address string
	InUse   bool
}

// Carrier is the resolution state of one configured carrier.
type Carrier struct {
	Name       string
	Host       string
	Transport  string
	Mode       string // "literal", "srv", "a", or "" until resolved
	Addresses  []CarrierAddress
	ResolvedAt time.Time // zero for a literal or unresolved carrier
	ExpiresAt  time.Time
	Failing    bool
	LastError  string
}

const (
	// defaultPageLimit and maxPageLimit bound one page of /api/registrations
	// and /api/shield/bans. A larger limit is clamped, not refused.
	defaultPageLimit = 100
	maxPageLimit     = 1000
	// maxUserFilter bounds the registrations user filter.
	maxUserFilter = 256
)

// pageParams parses limit and offset. A value that is not a non-negative
// integer (limit: positive) is a 400.
func pageParams(w http.ResponseWriter, r *http.Request) (limit, offset int, ok bool) {
	q := r.URL.Query()
	limit = defaultPageLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return 0, 0, false
		}
		limit = min(n, maxPageLimit)
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			http.Error(w, "offset must be a non-negative integer", http.StatusBadRequest)
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

// stateGET admits only GET (405 + Allow otherwise) and a configured
// closure (404 when nil, like /api/drain).
func stateGET(w http.ResponseWriter, r *http.Request, configured bool) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !configured {
		http.NotFound(w, r)
		return false
	}
	return true
}

// secondsUntil is the whole seconds from now to t, never negative.
func secondsUntil(t, now time.Time) int {
	return max(int(t.Sub(now).Seconds()), 0)
}

// rfc3339 renders t in UTC, or nil for the zero time (JSON null).
func rfc3339(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// handleRegistrations serves GET /api/registrations?user=&limit=&offset=:
// one page of the live client bindings and the total matching the filter.
func (s *Server) handleRegistrations(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.Registrations != nil) {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	user := r.URL.Query().Get("user")
	if len(user) > maxUserFilter {
		http.Error(w, "user filter too long", http.StatusBadRequest)
		return
	}
	regs, total := s.deps.Registrations(user, limit, offset)
	now := time.Now()
	items := make([]map[string]any, 0, len(regs))
	for _, g := range regs {
		items = append(items, map[string]any{
			"aor":        g.AOR,
			"user":       g.User,
			"transport":  g.Transport,
			"source":     g.Source,
			"expires_in": secondsUntil(g.ExpiresAt, now),
		})
	}
	writeJSON(w, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

// handleCarrierRegistrations serves GET /api/carrier-registrations: always
// an array.
func (s *Server) handleCarrierRegistrations(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.CarrierRegistrations != nil) {
		return
	}
	now := time.Now()
	out := []map[string]any{}
	for _, c := range s.deps.CarrierRegistrations() {
		out = append(out, map[string]any{
			"carrier":    c.Carrier,
			"user":       c.User,
			"token":      c.Token,
			"node":       c.Node,
			"expires_in": secondsUntil(c.Expires, now),
		})
	}
	writeJSON(w, out)
}

// handleBans serves GET /api/shield/bans?limit=&offset=: one page of the
// live bans, the total, and the cumulative ban additions refused at the ban
// table's cap.
func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.Bans != nil) {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	bans, total, rejected := s.deps.Bans(limit, offset)
	now := time.Now()
	items := make([]map[string]any, 0, len(bans))
	for _, b := range bans {
		items = append(items, map[string]any{
			"source":    b.Source,
			"kind":      b.Kind,
			"reason":    b.Reason,
			"since":     rfc3339(b.Since),
			"remaining": secondsUntil(b.Until, now),
		})
	}
	writeJSON(w, map[string]any{
		"items": items, "total": total, "limit": limit, "offset": offset,
		"ban_adds_rejected": rejected,
	})
}

// handleSwitchNodes serves GET /api/switch-nodes: always an array.
func (s *Server) handleSwitchNodes(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.SwitchNodes != nil) {
		return
	}
	out := []map[string]any{}
	for _, n := range s.deps.SwitchNodes() {
		out = append(out, map[string]any{
			"address":            n.Address,
			"state":              n.State,
			"cooldown_remaining": int(n.CooldownRemaining.Seconds()),
			"last_failure":       rfc3339(n.LastFailure),
		})
	}
	writeJSON(w, out)
}

// handleCarriers serves GET /api/carriers: always an array.
func (s *Server) handleCarriers(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.Carriers != nil) {
		return
	}
	now := time.Now()
	out := []map[string]any{}
	for _, c := range s.deps.Carriers() {
		addrs := make([]map[string]any, 0, len(c.Addresses))
		for _, a := range c.Addresses {
			addrs = append(addrs, map[string]any{"address": a.Address, "in_use": a.InUse})
		}
		var age any // null for a literal or never-resolved carrier
		if !c.ResolvedAt.IsZero() {
			age = max(int(now.Sub(c.ResolvedAt).Seconds()), 0)
		}
		out = append(out, map[string]any{
			"name":              c.Name,
			"host":              c.Host,
			"transport":         c.Transport,
			"mode":              c.Mode,
			"addresses":         addrs,
			"resolved_at":       rfc3339(c.ResolvedAt),
			"expires_at":        rfc3339(c.ExpiresAt),
			"cache_age_seconds": age,
			"failing":           c.Failing,
			"last_error":        c.LastError,
		})
	}
	writeJSON(w, out)
}
