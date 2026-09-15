package edge

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

// dialogState is where one proxied call stands in its life. The three
// states are the ones the code actually distinguishes — they are not a
// model of RFC 3261 §12, which is the endpoints' business, not a proxy's.
type dialogState int

const (
	// dialogEarly: an INVITE is in flight and no 2xx has been relayed. The
	// media session is allocated but not committed, and a CANCEL still
	// applies — the attempt below is what one is built from. A failover
	// series stays in this state across every attempt.
	dialogEarly dialogState = iota
	// dialogConfirmed: a 2xx was relayed. The media session is committed,
	// both endpoints' signaling addresses and Contacts are recorded, and
	// in-dialog requests are routed by this record.
	dialogConfirmed
	// dialogEnded: terminal. The media session is closed and the record is
	// out of the table. Every later end() is a no-op, which is what makes
	// the teardown paths safe to race one another.
	dialogEnded
)

// inviteAttempt is the INVITE FreeSBC currently has in flight for an early
// dialog.
//
// req is the request AS FORWARDED, because a CANCEL must carry the same
// top Via branch as the INVITE it cancels (RFC 3261 §9.1) and that branch
// is only in the forwarded copy. cancel is always the WHOLE series'
// cancel, never a per-attempt one, so a CANCEL that lands between two
// attempts still ends the series.
// fromTag is the CALLER's From tag, taken from the INVITE we received. A
// CANCEL carries the same Call-ID and the same From tag as the INVITE it
// cancels (RFC 3261 §9.1), so requiring it to match is what stops an
// orphan CANCEL that merely guessed a live Call-ID from tearing down
// somebody else's in-flight call.
type inviteAttempt struct {
	req     *sip.Request
	cancel  context.CancelFunc
	fromTag string
}

// dialogRoute is where an in-dialog request goes once the call is up.
//
// The remotes are transport source addresses (or, for the callee, the
// address the call was finally connected to), never a Contact host: a
// client behind NAT — and a browser, whose Contact host is a fiction —
// can only be reached at the address its packets came from.
//
// The contacts are the two endpoints' own Contact URIs, as they wrote
// them. They are needed because the proxy replaced both: each side was
// given FreeSBC's Contact as the dialog's remote target, so an in-dialog
// request from either arrives with FreeSBC's own URI as its Request-URI.
// Restoring the far endpoint's real Contact is what makes that request
// addressed to somebody — sofia tolerates the SBC's URI, a strict UA does
// not.
type dialogRoute struct {
	publicRemote  string
	privateRemote string
	transport     string

	publicContact  sip.Uri
	privateContact sip.Uri
}

// sdpOrigin is the o= identity FreeSBC uses for every body it generates on
// one dialog. The id must stay constant for the life of the session (RFC
// 4566): a changed id means a NEW session, which some endpoints answer by
// tearing the old one down. The version must increase on every body built
// for the same id, and some endpoints use it to decide whether a re-offer
// changed anything.
type sdpOrigin struct {
	id      uint64
	version uint64
}

// newSDPOrigin starts a session identity. RFC 4566 wants the id to be
// "globally unique"; a nanosecond clock reading is what every
// implementation actually uses.
func newSDPOrigin() sdpOrigin { return sdpOrigin{id: uint64(time.Now().UnixNano())} }

// next returns the identity and the next version for one generated body.
func (o *sdpOrigin) next() (id, version uint64) {
	o.version++
	return o.id, o.version
}

// dialog is one proxied call, from the first forwarded INVITE to the
// teardown of its media — the single owner of everything whose lifetime is
// the call's.
//
// The proxy does not own the dialog on the wire (the endpoints do), so
// this record holds only what the proxy needs: enough identity to match an
// in-dialog request, the media session whose lifetime must follow the
// dialog's, the CANCEL bridge while the INVITE is in flight, and the two
// pieces of signaling bookkeeping that must not be re-derived mid-call
// (the answer body already sent, and the o= identity).
//
// Every mutable field is guarded by the owning table's mutex; the record
// is never mutated directly outside this file.
type dialog struct {
	tab    *dialogTable
	callID string

	state    dialogState
	inFlight *inviteAttempt
	route    dialogRoute

	// media is the anchored session. It is attached once, right after the
	// record is created, and then only closed — never replaced.
	media *mediaSession

	// answer is the body FreeSBC built for the near side the first time
	// the far side answered. A 200 OK that restates the answer already
	// sent in a reliable provisional must repeat OUR body, not re-run
	// negotiation — re-latching mid-call would drop audio.
	answer []byte

	origin sdpOrigin
}

// dialogTable is the proxy's one store of calls, keyed by Call-ID.
//
// Call-ID alone, not the full RFC 3261 §12 dialog identifier, and not the
// Call-ID|from-tag the CANCEL bridge used to be keyed by. Two reasons, and
// they point the same way:
//
//   - An in-dialog request from the CALLEE carries the callee's tag in
//     From, so a from-tag key could not find the record that routes it.
//     Every in-dialog lookup (directionFor, farContact, the re-INVITE
//     path, teardown) is by Call-ID for exactly that reason.
//   - A CANCEL carries the same Call-ID and the same From tag as the
//     INVITE it cancels (§9.1), so the Call-ID alone finds the record.
//     The tag still has to agree before an attempt is cancelled, but that
//     is a check on the record (see inviteAttempt.fromTag), not a key.
//
// One entry per Call-ID also means FreeSBC anchors one media session per
// call: a forking upstream that produced two dialogs on one Call-ID would
// need two, which is a B2BUA's problem, not a proxy's. The limitation is
// real and documented; what matters here is that the table can never grow
// without bound, because every record leaves it through end().
type dialogTable struct {
	mu       sync.Mutex
	byCallID map[string]*dialog

	metrics *Metrics
	log     *slog.Logger
}

func newDialogTable(m *Metrics, log *slog.Logger) *dialogTable {
	return &dialogTable{byCallID: map[string]*dialog{}, metrics: m, log: log}
}

// begin opens an early dialog for a Call-ID a call is being placed on.
//
// A record already under that Call-ID is ended: a new out-of-dialog INVITE
// reusing a live Call-ID is the client abandoning the old call, and
// leaving the old media session anchored would orphan its ports.
func (t *dialogTable) begin(callID string) *dialog {
	d := &dialog{tab: t, callID: callID, origin: newSDPOrigin()}
	t.mu.Lock()
	prev := t.byCallID[callID]
	t.byCallID[callID] = d
	t.mu.Unlock()
	if prev != nil {
		prev.end()
	}
	return d
}

// get returns the record for a Call-ID in any state. It is the CANCEL
// bridge's lookup: a CANCEL applies to an early dialog.
func (t *dialogTable) get(callID string) (*dialog, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.byCallID[callID]
	return d, ok
}

// confirmed returns the record for a Call-ID only once the call is up. An
// in-dialog request has nothing to do with an INVITE still in flight, so
// every in-dialog path asks for this and not get.
func (t *dialogTable) confirmed(callID string) (*dialog, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.byCallID[callID]
	if !ok || d.state != dialogConfirmed {
		return nil, false
	}
	return d, true
}

// routeFor is confirmed plus the routing snapshot, which is all the
// in-dialog forwarding paths need.
func (t *dialogTable) routeFor(callID string) (dialogRoute, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.byCallID[callID]
	if !ok || d.state != dialogConfirmed {
		return dialogRoute{}, false
	}
	return d.route, true
}

// count is the number of calls that are up — the same number the dialog
// gauge carries.
func (t *dialogTable) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, d := range t.byCallID {
		if d.state == dialogConfirmed {
			n++
		}
	}
	return n
}

// closeAll ends every dialog. Called at shutdown so no socket, port
// reservation or relay goroutine outlives the process's SIP plane.
func (t *dialogTable) closeAll() {
	t.mu.Lock()
	all := make([]*dialog, 0, len(t.byCallID))
	for _, d := range t.byCallID {
		all = append(all, d)
	}
	t.mu.Unlock()
	for _, d := range all {
		d.end()
	}
}

// attach records the media session this dialog anchors. Called once, on
// the allocation that immediately follows begin.
func (d *dialog) attach(sess *mediaSession) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	d.media = sess
}

// session is the anchored media session, or nil before one is attached.
func (d *dialog) session() *mediaSession {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.media
}

// nextOrigin is the o= identity and version for a body FreeSBC is about to
// generate on this dialog.
func (d *dialog) nextOrigin() (id, version uint64) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.origin.next()
}

// lastAnswer is the answer body already sent to the near side, or nil if
// none has been.
func (d *dialog) lastAnswer() []byte {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.answer
}

// setLastAnswer records the answer body just sent to the near side.
func (d *dialog) setLastAnswer(b []byte) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	d.answer = b
}

// track points the CANCEL bridge at the INVITE now in flight. A failover
// series re-tracks per attempt, deliberately overwriting the previous
// entry: it is one dialog the caller is waiting on, whatever we had to try
// to connect it.
func (d *dialog) track(a *inviteAttempt) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	d.inFlight = a
}

// untrack clears the CANCEL bridge at the end of a series. Between two
// attempts the stale entry deliberately stays put, so a CANCEL in that
// window still ends the series through it.
func (d *dialog) untrack() {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	d.inFlight = nil
}

// takeAttempt removes and returns the in-flight INVITE, so exactly one
// caller ever cancels it. fromTag must be the From tag of the cancelling
// request: a mismatch leaves the attempt in place and reports none, so the
// caller treats it exactly like a CANCEL for a call it does not know.
func (d *dialog) takeAttempt(fromTag string) (*inviteAttempt, bool) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	a := d.inFlight
	if a == nil || a.fromTag != fromTag {
		return nil, false
	}
	d.inFlight = nil
	return a, true
}

// confirm promotes an early dialog to a confirmed one: the 2xx has been
// relayed, so the media session is committed and its lifetime is tied to
// the dialog's — whichever ends first, a BYE or the media watchdog
// noticing silence, tears the other down.
//
// A dialog that has already ended (shutdown racing the answer) is left
// ended: its media is closed and nothing may be committed on top of it.
func (d *dialog) confirm(r dialogRoute) {
	t := d.tab
	t.mu.Lock()
	if d.state != dialogEarly || d.media == nil {
		// Already ended, or no media was ever anchored: there is nothing
		// to commit on top of either.
		t.mu.Unlock()
		return
	}
	d.state = dialogConfirmed
	d.route = r
	sess := d.media
	t.mu.Unlock()

	t.metrics.DialogStarted()
	t.metrics.MediaStarted(sess.IsWebRTC())

	// One goroutine per call watching for the media session to end. It has
	// an explicit exit (the session's Done channel, closed by Close or by
	// the silence watchdog), so it cannot outlive the call.
	go func() {
		<-sess.Done()
		d.end()
	}()
}

// endUnlessUp ends a dialog whose INVITE never connected. It is what every
// INVITE path defers in place of the stack-local "committed" flag the three
// paths used to keep: the record's own state is the flag.
func (d *dialog) endUnlessUp() {
	d.tab.mu.Lock()
	early := d.state == dialogEarly
	d.tab.mu.Unlock()
	if early {
		d.end()
	}
}

// end is the single exit every teardown path goes through — a BYE, the
// media watchdog, shutdown, a failed INVITE, and a new call taking over
// the Call-ID. It closes the media session, drops the record and, for a
// call that was up, reports the dialog's end exactly once.
//
// Idempotent, and safe to race: the state transition under the table's
// mutex is what elects the one caller that does the work.
func (d *dialog) end() {
	t := d.tab
	t.mu.Lock()
	if d.state == dialogEnded {
		t.mu.Unlock()
		return
	}
	wasUp := d.state == dialogConfirmed
	d.state = dialogEnded
	d.inFlight = nil
	sess := d.media
	// Only if this record still owns the key: a later call on the same
	// Call-ID has its own record, which this teardown must not evict.
	if t.byCallID[d.callID] == d {
		delete(t.byCallID, d.callID)
	}
	t.mu.Unlock()

	if sess == nil {
		return
	}
	st := sess.Stats()
	webrtc := sess.IsWebRTC()
	_ = sess.Close()
	if !wasUp {
		// An INVITE that never connected: nothing was ever counted as
		// started, so nothing is counted as ended.
		return
	}
	t.metrics.DialogEnded()
	t.metrics.MediaEnded(webrtc, st)
	t.log.Info("call ended", "sip_call_id", d.callID, "stats", st)
}
