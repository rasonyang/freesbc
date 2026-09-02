package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Binding is one registered contact: everything the proxy needs to deliver
// an inbound request to a client, and nothing more.
//
// It is deliberately NOT a registration record. FreeSWITCH is the
// authoritative registrar: it owns the AoR, the credentials and the
// authoritative expiry. This table exists only because an inbound request
// from FreeSWITCH arrives addressed to a contact FreeSBC invented, and
// something has to turn that back into a real client address — and, for
// WebSocket clients, into the specific connection that client is on.
type Binding struct {
	// Token is the opaque identifier FreeSBC put in the Contact it
	// registered upstream. FreeSWITCH echoes it in the Request-URI of an
	// inbound request, which is how one of a user's several devices is
	// picked out.
	Token string
	// AOR is the address-of-record, "user@domain", lower-cased.
	AOR string
	// User is the AoR's user part, used to build the Request-URI sent to
	// the client.
	User string
	// Contact is the client's own Contact URI as it wrote it. For a
	// WebSocket client this is a fiction (sip.js writes an unreachable
	// ".invalid" host), which is exactly why Source below exists.
	Contact string
	// Transport is the public transport the client registered over.
	Transport string
	// Source is the transport source address the REGISTER actually came
	// from. This — never the Contact host — is where requests are sent:
	// it is the far side of the client's NAT pinhole for UDP, and the
	// pooled connection key for WS/WSS.
	Source netip.AddrPort
	// ExpiresAt is when FreeSWITCH said the registration lapses. It is
	// taken from the 200 OK, never from the phone's request: the registrar
	// may grant less than was asked for.
	ExpiresAt time.Time
	// CallID and CSeq identify the registration flow, so a refresh
	// replaces the right binding rather than creating a second one.
	CallID string
}

// Expired reports whether the binding has lapsed as of now.
func (b *Binding) Expired(now time.Time) bool { return !now.Before(b.ExpiresAt) }

// Location is the runtime table of registration bindings.
//
// Bounded on purpose (spec §16): an unauthenticated flood of REGISTERs
// that FreeSWITCH happens to accept must not be able to grow this map
// without limit. Entries are keyed by token and indexed by AoR.
type Location struct {
	mu       sync.RWMutex
	byToken  map[string]*Binding
	byAOR    map[string][]*Binding
	maxTotal int
	// maxPerAOR caps how many devices one user may have registered at
	// once, so a single compromised account cannot consume the table.
	maxPerAOR int
}

// Default table bounds. A single node targets a few thousand
// registrations; 20 000 leaves generous headroom while still being a
// bound. Ten devices per user is far above real usage.
const (
	defaultMaxBindings = 20000
	defaultMaxPerAOR   = 10
)

// ErrTooManyBindings is returned when the table is full; the caller maps
// it to a 503 rather than silently dropping the registration.
type ErrTooManyBindings struct{ Scope string }

func (e *ErrTooManyBindings) Error() string {
	return "proxy: registration table full (" + e.Scope + ")"
}

func NewLocation() *Location {
	return &Location{
		byToken:   map[string]*Binding{},
		byAOR:     map[string][]*Binding{},
		maxTotal:  defaultMaxBindings,
		maxPerAOR: defaultMaxPerAOR,
	}
}

// Put installs or refreshes a binding. A refresh is recognised by the
// (AoR, Call-ID) pair — the same client re-registering — and reuses the
// existing token, so the contact FreeSWITCH has stored stays valid across
// refreshes.
//
// It returns the stored binding, whose Token is the one to advertise
// upstream.
func (l *Location) Put(b Binding) (*Binding, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.pruneLocked(now)

	existing := l.byAOR[b.AOR]
	for _, e := range existing {
		if e.CallID == b.CallID {
			// Refresh in place: the token must not change, or FreeSWITCH
			// would be left holding a contact that no longer resolves.
			b.Token = e.Token
			*e = b
			return e, nil
		}
	}
	if len(existing) >= l.maxPerAOR {
		return nil, &ErrTooManyBindings{Scope: "per address-of-record"}
	}
	if len(l.byToken) >= l.maxTotal {
		return nil, &ErrTooManyBindings{Scope: "total"}
	}
	if b.Token == "" {
		b.Token = newToken()
	}
	nb := &b
	l.byToken[nb.Token] = nb
	l.byAOR[nb.AOR] = append(l.byAOR[nb.AOR], nb)
	return nb, nil
}

// Remove drops the binding for an (AoR, Call-ID) pair — an explicit
// un-REGISTER (Expires: 0). It returns the removed binding, if any.
func (l *Location) Remove(aor, callID string) *Binding {
	l.mu.Lock()
	defer l.mu.Unlock()
	list := l.byAOR[aor]
	for i, e := range list {
		if e.CallID == callID {
			l.deleteLocked(aor, i)
			return e
		}
	}
	return nil
}

// RemoveBySource drops every binding registered from a given source
// address. Called when a WebSocket connection closes: the client is gone
// and its bindings can no longer be delivered to, so keeping them would
// leak table entries until their expiry and, worse, make FreeSBC accept
// inbound calls it cannot deliver.
func (l *Location) RemoveBySource(src netip.AddrPort) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for aor, list := range l.byAOR {
		for i := len(list) - 1; i >= 0; i-- {
			if list[i].Source == src {
				l.deleteLocked(aor, i)
				list = l.byAOR[aor]
				n++
			}
		}
	}
	return n
}

// deleteLocked removes index i of an AoR's list. Caller holds the lock.
func (l *Location) deleteLocked(aor string, i int) {
	list := l.byAOR[aor]
	delete(l.byToken, list[i].Token)
	list = append(list[:i], list[i+1:]...)
	if len(list) == 0 {
		delete(l.byAOR, aor)
		return
	}
	l.byAOR[aor] = list
}

// ByToken looks up the binding FreeSWITCH addressed. Expired bindings are
// not returned.
func (l *Location) ByToken(token string) (Binding, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	b, ok := l.byToken[token]
	if !ok || b.Expired(time.Now()) {
		return Binding{}, false
	}
	return *b, true
}

// ByAOR returns every live binding for an address-of-record. It is the
// fallback when an inbound Request-URI carries no token — for instance
// from a FreeSWITCH dialplan that rewrote the contact.
func (l *Location) ByAOR(aor string) []Binding {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	var out []Binding
	for _, b := range l.byAOR[strings.ToLower(aor)] {
		if !b.Expired(now) {
			out = append(out, *b)
		}
	}
	return out
}

// Count is the number of live bindings, for metrics.
func (l *Location) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.byToken)
}

// Prune drops expired bindings. Called periodically by the proxy so a
// client that vanishes without un-registering does not hold an entry past
// its registrar-granted lifetime.
func (l *Location) Prune() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pruneLocked(time.Now())
}

func (l *Location) pruneLocked(now time.Time) int {
	n := 0
	for aor, list := range l.byAOR {
		for i := len(list) - 1; i >= 0; i-- {
			if list[i].Expired(now) {
				l.deleteLocked(aor, i)
				list = l.byAOR[aor]
				n++
			}
		}
	}
	return n
}

// Snapshot returns every live binding, for the admin API.
func (l *Location) Snapshot() []Binding {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	out := make([]Binding, 0, len(l.byToken))
	for _, b := range l.byToken {
		if !b.Expired(now) {
			out = append(out, *b)
		}
	}
	return out
}

// newToken generates the opaque contact identifier. It is a capability in
// the weak sense — anything that knows a token can address that device
// through FreeSWITCH — so it is drawn from crypto/rand rather than a
// counter, and is long enough not to be guessable.
func newToken() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice; falling back to a
		// timestamp would produce a guessable token, so panic is the
		// honest response to an impossible condition.
		panic("proxy: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
