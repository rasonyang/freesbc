package edge

import (
	fsip "github.com/freesbc/freesbc/internal/sip"
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
// without limit. Entries are keyed by token and indexed by AoR and by
// transport source. The three maps always hold the same set of bindings:
// every insertion goes through Put and every removal through
// deleteLocked.
type Location struct {
	mu      sync.RWMutex
	byToken map[string]*Binding
	byAOR   map[string][]*Binding
	// bySource indexes bindings by the transport source address the
	// REGISTER came from (Binding.Source). It is what the INVITE admission
	// check (HasSource) and the WebSocket close hook (RemoveBySource) look
	// up, so neither scans the table. One source may hold several bindings
	// (a phone registering several lines over one socket).
	bySource map[netip.AddrPort][]*Binding
	maxTotal int
	// maxPerAOR caps how many devices one user may have registered at
	// once, so a single compromised account cannot consume the table.
	maxPerAOR int

	// onRemove, when set, is told the tokens of bindings that left the
	// table (SetOnRemove). removed collects them under mu; the mutating
	// methods hand them over only after mu is released, so the hook may
	// take its own locks without an ordering constraint.
	onRemove func(tokens []string)
	removed  []string
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
		bySource:  map[netip.AddrPort][]*Binding{},
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
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Only THIS AoR is swept, not the whole table: a REGISTER is the
	// hottest path here and sweeping every binding on each one makes the
	// cost of one registration grow with the size of the table. What the
	// sweep is needed for is local — a device whose previous binding has
	// lapsed must not count against the per-AoR cap — and reclaiming
	// everyone else's expired bindings is the periodic Prune's job.
	l.pruneAORLocked(b.AOR, time.Now())

	existing := l.byAOR[b.AOR]
	for _, e := range existing {
		if e.CallID == b.CallID {
			// Refresh in place: the token must not change, or FreeSWITCH
			// would be left holding a contact that no longer resolves.
			b.Token = e.Token
			// The refresh may come from a new source (the phone's NAT
			// mapping changed), so re-index under the new address.
			l.unindexSourceLocked(e)
			*e = b
			l.indexSourceLocked(e)
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
		b.Token = fsip.NewToken()
	}
	nb := &b
	l.byToken[nb.Token] = nb
	l.byAOR[nb.AOR] = append(l.byAOR[nb.AOR], nb)
	l.indexSourceLocked(nb)
	return nb, nil
}

// Remove drops the binding for an (AoR, Call-ID) pair — an explicit
// un-REGISTER (Expires: 0). It returns the removed binding, if any.
func (l *Location) Remove(aor, callID string) *Binding {
	defer l.flushRemoved()
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
	return l.removeBySource("", src)
}

// RemoveBySourceOn is RemoveBySource limited to bindings registered over
// transport, compared case-insensitively. A stream connection closing must
// not take a UDP binding that has the same IP:port.
func (l *Location) RemoveBySourceOn(transport string, src netip.AddrPort) int {
	return l.removeBySource(transport, src)
}

func (l *Location) removeBySource(transport string, src netip.AddrPort) int {
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Copy: deleteLocked edits the index slice being walked.
	var victims []*Binding
	for _, b := range l.bySource[src] {
		if transport == "" || strings.EqualFold(b.Transport, transport) {
			victims = append(victims, b)
		}
	}
	for _, b := range victims {
		for i, e := range l.byAOR[b.AOR] {
			if e == b {
				l.deleteLocked(b.AOR, i)
				break
			}
		}
	}
	return len(victims)
}

// HasSource reports whether a live (unexpired) binding was registered over
// transport from exactly src. It is the edge INVITE admission check: a
// public client may place a call from the transport address its
// registration came from. transport is compared case-insensitively.
func (l *Location) HasSource(transport string, src netip.AddrPort) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	for _, b := range l.bySource[src] {
		if strings.EqualFold(b.Transport, transport) && !b.Expired(now) {
			return true
		}
	}
	return false
}

// SourceBinding returns a live binding registered over transport from
// exactly src: the one whose User equals user (case-insensitively), else
// the first live one. ok is false when the source holds none. It is
// HasSource that also says which registration the source is.
func (l *Location) SourceBinding(transport string, src netip.AddrPort, user string) (Binding, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	var first *Binding
	for _, b := range l.bySource[src] {
		if !strings.EqualFold(b.Transport, transport) || b.Expired(now) {
			continue
		}
		if user != "" && strings.EqualFold(b.User, user) {
			return *b, true
		}
		if first == nil {
			first = b
		}
	}
	if first == nil {
		return Binding{}, false
	}
	return *first, true
}

// indexSourceLocked adds b to the source index. Caller holds the lock.
func (l *Location) indexSourceLocked(b *Binding) {
	l.bySource[b.Source] = append(l.bySource[b.Source], b)
}

// unindexSourceLocked removes b from the source index. Caller holds the
// lock.
func (l *Location) unindexSourceLocked(b *Binding) {
	list := l.bySource[b.Source]
	for i, e := range list {
		if e == b {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(l.bySource, b.Source)
		return
	}
	l.bySource[b.Source] = list
}

// deleteLocked removes index i of an AoR's list, and the binding from every
// other index. Caller holds the lock.
func (l *Location) deleteLocked(aor string, i int) {
	list := l.byAOR[aor]
	delete(l.byToken, list[i].Token)
	if l.onRemove != nil {
		l.removed = append(l.removed, list[i].Token)
	}
	l.unindexSourceLocked(list[i])
	list = append(list[:i], list[i+1:]...)
	if len(list) == 0 {
		delete(l.byAOR, aor)
		return
	}
	l.byAOR[aor] = list
}

// SetOnRemove registers f to be told the tokens of bindings that are
// removed (un-REGISTER, WebSocket close, expiry, the per-AoR sweep in Put).
// f runs after the table's lock is released, on the goroutine that made the
// change, so it may take locks of its own. A binding that is refreshed in
// place keeps its token and is not reported. Call it before the table is
// shared.
func (l *Location) SetOnRemove(f func(tokens []string)) {
	l.mu.Lock()
	l.onRemove = f
	l.mu.Unlock()
}

// flushRemoved hands the tokens collected by deleteLocked to the hook. It
// must run with mu NOT held (the mutating methods defer it before taking
// the lock, so it runs after their unlock).
func (l *Location) flushRemoved() {
	l.mu.Lock()
	f, tokens := l.onRemove, l.removed
	l.removed = nil
	l.mu.Unlock()
	if f != nil && len(tokens) > 0 {
		f(tokens)
	}
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
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pruneLocked(time.Now())
}

func (l *Location) pruneLocked(now time.Time) int {
	n := 0
	for aor := range l.byAOR {
		n += l.pruneAORLocked(aor, now)
	}
	return n
}

// pruneAORLocked drops one address-of-record's expired bindings and
// returns how many went. Caller holds the lock.
func (l *Location) pruneAORLocked(aor string, now time.Time) int {
	n := 0
	list := l.byAOR[aor]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Expired(now) {
			l.deleteLocked(aor, i)
			list = l.byAOR[aor]
			n++
		}
	}
	return n
}
