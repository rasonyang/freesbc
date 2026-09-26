package edge

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// dialogState is where one proxied call stands in its life. The three
// states are the ones the code actually distinguishes.
type dialogState int

const (
	// dialogEarly: an INVITE is in flight and no 2xx has been relayed. The
	// media session is allocated but not committed, and a CANCEL still
	// applies — the attempt below is what one is built from. A failover
	// series stays in this state across every attempt, and every early
	// dialog the far side opens (one per To tag, see earlyFork) hangs off
	// this one record.
	dialogEarly dialogState = iota
	// dialogConfirmed: a 2xx was accepted. The record now names exactly one
	// dialog — Call-ID, the caller's tag and the answering fork's tag — the
	// media session is committed, both endpoints' signaling addresses and
	// Contacts are recorded, and in-dialog requests carrying those three
	// identifiers are routed by this record.
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
//
// An attempt is tracked BEFORE its INVITE is sent, so a CANCEL can never
// fall in a window where the INVITE is out but untracked. sent and
// cancelled (guarded by the table's mutex) settle the one race that is
// left: a CANCEL that takes the attempt before the INVITE is on the wire
// must not send its CANCEL ahead of the INVITE (the next hop would answer
// 481 and then ring), so it leaves that to the sender, which CANCELs as
// soon as markSent tells it the attempt was taken.
type inviteAttempt struct {
	req    *sip.Request
	cancel context.CancelFunc

	sent, cancelled bool
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

// sdpOrigin is the o= identity FreeSBC uses for the bodies it generates
// toward ONE leg of one dialog. The id must stay constant for the life of
// the session (RFC 4566): a changed id means a NEW session, which some
// endpoints answer by tearing the old one down. The version must go up by
// exactly one on every new body the same leg is sent (RFC 3264 §8), which
// is why there is one origin per leg rather than one per call: a shared
// counter would advance for the other leg's bodies too, and each endpoint
// would see its versions jump.
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

// earlyFork is one early dialog the far side opened on the INVITE FreeSBC
// forwarded, identified by the To tag its responses carry (RFC 3261
// §12.1.2, §13.2.2.4).
//
// Each fork's answer is its own (RFC 3264 §6): the body FreeSBC built for
// the caller from it, the codecs it agreed, the media address it signalled
// and the o= identity of the bodies the caller is sent on its behalf. A
// later response on the same fork that restates the answer gets the SAME
// body again; a response on another fork is negotiated afresh, and the
// anchored media follows whichever fork answered last — and, once one of
// them sends a 2xx, that one.
type earlyFork struct {
	answer []byte
	codecs []sdp.Codec
	remote netip.AddrPort
	rtcp   netip.AddrPort // explicit a=rtcp, when the answer carried one
	origin sdpOrigin
}

// dialog is one proxied call, from the first forwarded INVITE to the
// teardown of its media — the single owner of everything whose lifetime is
// the call's.
//
// The proxy does not own the dialog on the wire (the endpoints do), so
// this record holds only what the proxy needs: the dialog identifiers to
// match an in-dialog request against, the media session whose lifetime
// must follow the dialog's, the CANCEL bridge while the INVITE is in
// flight, the per-fork answers while it is early, and the per-leg o=
// identities.
//
// Every mutable field is guarded by the owning table's mutex; the record
// is never mutated directly outside this file.
type dialog struct {
	tab    *dialogTable
	callID string
	// callerTag is the From tag of the INVITE that opened the record.
	// calleeTag is the To tag of the 2xx that confirmed it; empty while
	// early. Together with the Call-ID they are the RFC 3261 §12 dialog
	// identifier, and an in-dialog request must name both to be routed by
	// this record.
	callerTag string
	calleeTag string
	// callerPlane is the plane the caller's in-dialog requests arrive on.
	// A request whose tags say "from the caller" but which arrived on the
	// other plane is not this dialog's.
	callerPlane plane

	state    dialogState
	inFlight *inviteAttempt
	route    dialogRoute

	// cancelled is set, synchronously, the moment the caller's CANCEL (or
	// the INVITE backstop) gives up on the call. From then on no 2xx may
	// confirm the record: sipgo answers the caller 487 as soon as the
	// OnCancel hook returns, so a 2xx relayed after that would confirm a
	// call the caller has already been told is over. callerGone says the
	// caller's own transaction has been finalised by sipgo (a CANCEL, not
	// the backstop), so nothing more may be sent on it.
	cancelled, callerGone bool

	// The dialog's two identities, as the caller's INVITE named them (the
	// From and To addresses; the tags are above), and the highest CSeq each
	// endpoint has used in it (index 0 the caller, 1 the callee). They are
	// what a BYE FreeSBC originates itself — when the media ends the call —
	// is built from: RFC 3261 §12.2.1.1 wants the sender's local CSeq to go
	// up, and the proxy can only know it by watching.
	callerURI, calleeURI sip.Uri
	cseq                 [2]uint32

	// confirmedAt is when the record was confirmed (the admin call list's
	// start time). Written under tab.mu in confirm.
	confirmedAt time.Time

	// media is the anchored session. It is attached once, right after the
	// record is created, and then only closed — never replaced.
	media *mediaSession

	// forks holds the early dialogs by To tag, and applied names the one
	// whose answer the media currently follows. Both are cleared on
	// confirmation: the confirmed fork's state moves into the record.
	forks   map[string]*earlyFork
	applied *earlyFork

	// ok is the 2xx as relayed to the caller. The far end retransmits its
	// 2xx until the caller's ACK reaches it, and each retransmission is
	// answered by relaying this same response again (RFC 3261 §13.3.1.4,
	// RFC 6026 §7.2) — never re-negotiated.
	ok *sip.Response
	// rejected records the To tags of 2xx responses FreeSBC refused to
	// relay (another fork's 2xx after this record was confirmed, or one it
	// could not anchor) and has already ACKed and BYEd: a retransmission
	// of one is only re-ACKed.
	rejected map[string]bool

	// origin is the o= identity per leg, indexed by plane.
	origin [2]sdpOrigin

	// relaxedNotify is set the first time a private-plane NOTIFY whose
	// tags name no dialog was routed to this record by Call-ID alone
	// (issue #84; see relaxedNotifyDirection), so the WARN is logged once
	// per dialog rather than once per retry.
	relaxedNotify bool
}

// dialogTable is the proxy's one store of calls.
//
// Records are grouped by Call-ID for lookup, and a Call-ID may carry more
// than one: RFC 3261 §12 identifies a dialog by the Call-ID AND both tags,
// so two calls that share a Call-ID (a client that reuses one, or a
// spiral) are two records, and a request is matched against a record's
// tags before anything acts on it. Every record leaves the table through
// end(), so it can never grow without bound.
type dialogTable struct {
	mu       sync.Mutex
	byCallID map[string][]*dialog

	// closed is set when shutdown begins (see close): from then on no
	// dialog is opened and no media is attached, so an INVITE still in
	// flight can neither allocate after shutdown began nor leak what it
	// allocated (audit P2-EDG-027).
	closed bool

	// onMediaEnd is called, once, for a confirmed dialog that ended because
	// its media did (the silence watchdog, a DTLS fingerprint mismatch),
	// rather than by signaling. Both endpoints still believe the call is
	// up, so the server tells them. Set once, before any call exists.
	onMediaEnd func(d *dialog)

	metrics *Metrics
	log     *slog.Logger
}

func newDialogTable(m *Metrics, log *slog.Logger) *dialogTable {
	return &dialogTable{byCallID: map[string][]*dialog{}, metrics: m, log: log}
}

// begin opens an early dialog for an INVITE a call is being placed with.
//
// It refuses (ok false) when an early record with the same Call-ID and
// caller tag already exists: that is a second INVITE for a transaction
// still in progress — a merged request (RFC 3261 §8.2.2.2), which the
// caller answers 482. A CONFIRMED record with the same identifiers is
// left alone: the new INVITE opens a new record beside it, and only the
// tags of later requests decide which one they belong to. An INVITE can
// therefore never tear down somebody else's call by reusing its Call-ID.
func (t *dialogTable) begin(req *sip.Request, callerPlane plane) (*dialog, bool) {
	callID, callerTag := fsip.CallID(req), fsip.FromTag(req)
	d := &dialog{
		tab:         t,
		callID:      callID,
		callerTag:   callerTag,
		callerPlane: callerPlane,
		forks:       map[string]*earlyFork{},
		origin:      [2]sdpOrigin{newSDPOrigin(), newSDPOrigin()},
		cseq:        [2]uint32{fsip.CSeqNumber(req), 0},
	}
	if f := req.From(); f != nil {
		d.callerURI = f.Address
	}
	if to := req.To(); to != nil {
		d.calleeURI = to.Address
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, false // shutting down; see isClosed
	}
	for _, o := range t.byCallID[callID] {
		if o.state == dialogEarly && o.callerTag == callerTag {
			return nil, false
		}
	}
	t.byCallID[callID] = append(t.byCallID[callID], d)
	return d, true
}

// early returns the in-flight record a CANCEL applies to: same Call-ID and
// the same From tag as the INVITE it cancels (RFC 3261 §9.1). The tag is
// what stops a CANCEL that merely guessed a live Call-ID from ending
// somebody else's call.
func (t *dialogTable) early(callID, callerTag string) (*dialog, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range t.byCallID[callID] {
		if d.state == dialogEarly && d.callerTag == callerTag {
			return d, true
		}
	}
	return nil, false
}

// lookup finds the confirmed dialog an in-dialog request belongs to. The
// request must name both tags: from the caller, its From tag is the
// caller's and its To tag the callee's; from the callee, the other way
// round. fromCaller reports which.
func (t *dialogTable) lookup(callID, fromTag, toTag string) (d *dialog, fromCaller, ok bool) {
	if fromTag == "" || toTag == "" {
		return nil, false, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range t.byCallID[callID] {
		if d.state != dialogConfirmed {
			continue
		}
		switch {
		case fromTag == d.callerTag && toTag == d.calleeTag:
			return d, true, true
		case fromTag == d.calleeTag && toTag == d.callerTag:
			return d, false, true
		}
	}
	return nil, false, false
}

// newestRoutedByCallID returns the most recently created record carrying
// callID that has a public route to send to (route.publicRemote set), with
// that route. It exists for one caller: onInDialog's relaxed routing of a
// private-plane NOTIFY whose tags name no dialog (issue #84).
//
// Records are appended to byCallID in creation order (begin), so the
// newest is the last one that qualifies. Only a confirmed record has a
// route: dialogRoute is written in confirm and nowhere else, so an early
// record never qualifies and the choice is, in effect, the newest
// confirmed dialog. An ended record is already out of the table.
func (t *dialogTable) newestRoutedByCallID(callID string) (*dialog, dialogRoute, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ds := t.byCallID[callID]
	for i := len(ds) - 1; i >= 0; i-- {
		d := ds[i]
		if d.state == dialogEnded || d.route.publicRemote == "" {
			continue
		}
		return d, d.route, true
	}
	return nil, dialogRoute{}, false
}

// count is the number of calls that are up — the same number the dialog
// gauge carries.
func (t *dialogTable) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, ds := range t.byCallID {
		for _, d := range ds {
			if d.state == dialogConfirmed {
				n++
			}
		}
	}
	return n
}

// CallRecord is one confirmed dialog as the admin API lists it.
type CallRecord struct {
	// ID identifies the dialog: "edge:" + Call-ID + ";" + caller tag.
	ID     string
	CallID string
	// From/To are the planes the caller and the callee are on.
	From, To      string
	StartUnixNano int64
}

// calls lists the confirmed dialogs: the same set count counts.
func (t *dialogTable) calls() []CallRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []CallRecord
	for _, ds := range t.byCallID {
		for _, d := range ds {
			if d.state != dialogConfirmed {
				continue
			}
			from, to := "edge:public", "edge:private"
			if d.callerPlane != planePublic {
				from, to = to, from
			}
			out = append(out, CallRecord{
				ID: "edge:" + d.callID + ";" + d.callerTag, CallID: d.callID,
				From: from, To: to, StartUnixNano: d.confirmedAt.UnixNano(),
			})
		}
	}
	return out
}

// close refuses every later begin and attach. Run calls it the moment
// shutdown begins, before the listeners close; closeAll then ends what is
// left.
func (t *dialogTable) close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
}

// isClosed reports whether close has run.
func (t *dialogTable) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// closeAll ends every dialog. Called at shutdown so no socket, port
// reservation or relay goroutine outlives the process's SIP plane.
func (t *dialogTable) closeAll() {
	t.mu.Lock()
	var all []*dialog
	for _, ds := range t.byCallID {
		all = append(all, ds...)
	}
	t.mu.Unlock()
	for _, d := range all {
		d.end()
	}
}

// removeLocked drops d from the table. The caller holds t.mu.
func (t *dialogTable) removeLocked(d *dialog) {
	ds := t.byCallID[d.callID]
	for i, o := range ds {
		if o != d {
			continue
		}
		ds = append(ds[:i:i], ds[i+1:]...)
		break
	}
	if len(ds) == 0 {
		delete(t.byCallID, d.callID)
		return
	}
	t.byCallID[d.callID] = ds
}

// errShuttingDown refuses a call because the proxy is shutting down.
var errShuttingDown = errors.New("proxy: shutting down")

// attach records the media session this dialog anchors. Called once, on
// the allocation that immediately follows begin. When the dialog can no
// longer own it — shutdown began, or the dialog already ended — the
// session is closed here instead and errShuttingDown returned: nothing
// else would ever close it.
func (d *dialog) attach(sess *mediaSession) error {
	d.tab.mu.Lock()
	if d.tab.closed || d.state == dialogEnded {
		d.tab.mu.Unlock()
		_ = sess.Close()
		return errShuttingDown
	}
	d.media = sess
	d.tab.mu.Unlock()
	return nil
}

// open reports whether media may still be allocated for d: shutdown has
// not begun and the dialog has not ended. Checked before allocating, so a
// handler in flight does not bind ports after shutdown began; attach is
// the authoritative check.
func (d *dialog) open() bool {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return !d.tab.closed && d.state != dialogEnded
}

// session is the anchored media session, or nil before one is attached.
func (d *dialog) session() *mediaSession {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.media
}

// routeSnapshot is the confirmed dialog's routing record.
func (d *dialog) routeSnapshot() dialogRoute {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.route
}

// tags returns the dialog's caller and callee tags. The callee tag is
// empty while the dialog is early.
func (d *dialog) tags() (caller, callee string) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.callerTag, d.calleeTag
}

// noteRelaxedNotify records that a NOTIFY was routed to this dialog by
// Call-ID alone (issue #84) and reports whether it was the first time, so
// the proxy warns once per dialog and logs the retries at Debug.
func (d *dialog) noteRelaxedNotify() (first bool) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	first = !d.relaxedNotify
	d.relaxedNotify = true
	return first
}

// nextOrigin is the o= identity and version for a body FreeSBC is about to
// send toward one leg of this dialog.
func (d *dialog) nextOrigin(toward plane) (id, version uint64) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.origin[toward].next()
}

// fork returns the early dialog for a To tag, creating it on first sight.
func (d *dialog) fork(tag string) *earlyFork {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	f, ok := d.forks[tag]
	if !ok {
		// A fresh o= identity per fork: each is a separate dialog, and so a
		// separate session, as far as the caller can tell.
		f = &earlyFork{origin: newSDPOrigin()}
		d.forks[tag] = f
	}
	return f
}

// forkAnswer is the answer already built for a fork, or nil.
func (d *dialog) forkAnswer(f *earlyFork) []byte {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return f.answer
}

// setForkAnswer records a fork's negotiated answer.
func (d *dialog) setForkAnswer(f *earlyFork, body []byte, codecs []sdp.Codec, remote, rtcp netip.AddrPort) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	f.answer, f.codecs, f.remote, f.rtcp = body, codecs, remote, rtcp
}

// forkMedia is what a fork's answer signalled and agreed.
func (d *dialog) forkMedia(f *earlyFork) (remote, rtcp netip.AddrPort, codecs []sdp.Codec) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return f.remote, f.rtcp, f.codecs
}

// nextForkOrigin is the o= identity for a body built for the caller on
// behalf of one fork.
func (d *dialog) nextForkOrigin(f *earlyFork) (id, version uint64) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return f.origin.next()
}

// lastApplied is the fork whose answer the media currently follows, or nil.
func (d *dialog) lastApplied() *earlyFork {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.applied
}

// setApplied records the fork whose answer the media now follows.
func (d *dialog) setApplied(f *earlyFork) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	d.applied = f
}

// relayed2xx is the 2xx relayed to the caller when calleeTag is the
// dialog's own, or nil.
func (d *dialog) relayed2xx(calleeTag string) *sip.Response {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	if d.state != dialogConfirmed || d.calleeTag != calleeTag || d.ok == nil {
		return nil
	}
	return d.ok
}

// setRelayed2xx records the 2xx as relayed, for its retransmissions.
func (d *dialog) setRelayed2xx(res *sip.Response) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	d.ok = res
}

// reject2xx records a 2xx FreeSBC refuses to relay and reports whether it
// is the first time: the first sighting is ACKed and BYEd, a
// retransmission only re-ACKed.
func (d *dialog) reject2xx(calleeTag string) (first bool) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	if d.rejected == nil {
		d.rejected = map[string]bool{}
	}
	if d.rejected[calleeTag] {
		return false
	}
	d.rejected[calleeTag] = true
	return true
}

// track points the CANCEL bridge at the INVITE about to be sent. A
// failover series re-tracks per attempt, deliberately overwriting the
// previous entry: it is one dialog the caller is waiting on, whatever we
// had to try to connect it. It refuses (false) once the series has been
// cancelled: the INVITE must then not be sent at all.
func (d *dialog) track(a *inviteAttempt) bool {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	if d.cancelled {
		return false
	}
	d.inFlight = a
	return true
}

// markSent records that a tracked attempt's INVITE is on the wire, and
// reports whether a CANCEL took the attempt before it was: the sender must
// then send that CANCEL itself, now that it can follow the INVITE.
func (d *dialog) markSent(a *inviteAttempt) (cancelNow bool) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	a.sent = true
	return a.cancelled
}

// untrack clears the CANCEL bridge at the end of a series. Between two
// attempts the stale entry deliberately stays put, so a CANCEL in that
// window still ends the series through it.
func (d *dialog) untrack() {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	d.inFlight = nil
}

// cancelReason says who is giving up on a call.
type cancelReason int

const (
	// cancelByCaller: the caller's CANCEL matched its INVITE's server
	// transaction, which sipgo has therefore already finalised (487).
	cancelByCaller cancelReason = iota
	// cancelOrphan: a CANCEL sipgo could not match, found by Call-ID and
	// From tag. It only acts on an attempt actually in flight.
	cancelOrphan
	// cancelBackstop: the INVITE's own budget ran out; the caller is still
	// waiting for a final response.
	cancelBackstop
)

// cancelSeries gives up on the call: no 2xx may confirm it from now on,
// and the in-flight INVITE, if any, is taken — removed, so exactly one
// caller ever cancels it. sendNow says whether that INVITE is already on
// the wire and needs a CANCEL now; when it is not, markSent hands the
// CANCEL to the sender.
func (d *dialog) cancelSeries(why cancelReason) (a *inviteAttempt, sendNow bool) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	a = d.inFlight
	if a == nil && why == cancelOrphan {
		// Nothing in flight: an orphan CANCEL between two attempts has
		// nothing to act on, and must not end the series.
		return nil, false
	}
	d.cancelled = true
	if why == cancelByCaller {
		d.callerGone = true
	}
	if a == nil {
		return nil, false
	}
	d.inFlight = nil
	a.cancelled = true
	return a, a.sent
}

// wasCancelled reports whether the call has been given up on.
func (d *dialog) wasCancelled() bool {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.cancelled
}

// callerCancelled reports whether the caller's transaction was finalised
// by its own CANCEL, so no response may be sent on it.
func (d *dialog) callerCancelled() bool {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.callerGone
}

// noteCSeq records the CSeq of an in-dialog request, by the endpoint that
// sent it.
func (d *dialog) noteCSeq(req *sip.Request) {
	seq := fsip.CSeqNumber(req)
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	i := 1
	if fsip.FromTag(req) == d.callerTag {
		i = 0
	}
	if seq > d.cseq[i] {
		d.cseq[i] = seq
	}
}

// byeInfo is what a BYE FreeSBC originates toward one endpoint needs.
type byeInfo struct {
	callID string
	// toward names the endpoint the BYE goes to; the BYE is sent on
	// behalf of the other one.
	toward    plane
	fromURI   sip.Uri
	fromTag   string
	toURI     sip.Uri
	toTag     string
	cseq      uint32
	remote    string
	contact   sip.Uri
	transport string
}

// byes describes the two BYEs that end this dialog from the middle: one to
// the caller on the callee's behalf, one to the callee on the caller's.
func (d *dialog) byes() [2]byeInfo {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	r := d.route
	at := func(p plane) (string, sip.Uri) {
		if p == planePublic {
			return r.publicRemote, r.publicContact
		}
		return r.privateRemote, r.privateContact
	}
	calleePlane := otherPlane(d.callerPlane)
	cRemote, cContact := at(d.callerPlane)
	eRemote, eContact := at(calleePlane)
	return [2]byeInfo{
		{callID: d.callID, toward: d.callerPlane,
			fromURI: d.calleeURI, fromTag: d.calleeTag, toURI: d.callerURI, toTag: d.callerTag,
			cseq: d.cseq[1] + 1, remote: cRemote, contact: cContact, transport: r.transport},
		{callID: d.callID, toward: calleePlane,
			fromURI: d.callerURI, fromTag: d.callerTag, toURI: d.calleeURI, toTag: d.calleeTag,
			cseq: d.cseq[0] + 1, remote: eRemote, contact: eContact, transport: r.transport},
	}
}

// confirm promotes an early dialog to a confirmed one: a 2xx from the fork
// tagged calleeTag was accepted, so the record now names exactly that
// dialog, the fork's state becomes the dialog's, and the media session's
// lifetime is tied to the dialog's — whichever ends first, a BYE or the
// media watchdog noticing silence, tears the other down.
//
// It runs BEFORE the 2xx is relayed, so the ACK the caller sends the
// moment it sees the 2xx always finds the record.
//
// It reports false for a dialog that has already ended (shutdown racing
// the answer), has no media, or was cancelled: nothing may be committed on
// top of any of them.
func (d *dialog) confirm(calleeTag string, r dialogRoute) bool {
	t := d.tab
	t.mu.Lock()
	if d.state != dialogEarly || d.media == nil || d.cancelled {
		t.mu.Unlock()
		return false
	}
	d.state = dialogConfirmed
	d.calleeTag = calleeTag
	d.confirmedAt = time.Now()
	d.route = r
	if f := d.forks[calleeTag]; f != nil && f.answer != nil {
		// The caller has seen this fork's bodies, so its o= identity is the
		// caller leg's from now on.
		d.origin[d.callerPlane] = f.origin
	} else if d.applied != nil {
		d.origin[d.callerPlane] = d.applied.origin
	}
	d.forks, d.applied = nil, nil
	sess := d.media
	t.mu.Unlock()

	t.metrics.DialogStarted()
	t.metrics.MediaStarted(sess.IsWebRTC())

	// One goroutine per call watching for the media session to end. It has
	// an explicit exit (the session's Done channel, closed by Close or by
	// the silence watchdog), so it cannot outlive the call.
	go func() {
		<-sess.Done()
		// Whoever ended the dialog first closed the session; only when the
		// media ended it — nobody else had — are the endpoints still to be
		// told.
		if d.end() && t.onMediaEnd != nil {
			t.onMediaEnd(d)
		}
	}()
	return true
}

// endUnlessUp ends a dialog whose INVITE never connected. It is what every
// INVITE path defers: the record's own state is the flag.
func (d *dialog) endUnlessUp() {
	d.tab.mu.Lock()
	early := d.state == dialogEarly
	d.tab.mu.Unlock()
	if early {
		d.end()
	}
}

// end is the single exit every teardown path goes through — a BYE, the
// media watchdog, shutdown and a failed INVITE. It closes the media
// session, drops the record and, for a call that was up, reports the
// dialog's end exactly once.
//
// Idempotent, and safe to race: the state transition under the table's
// mutex is what elects the one caller that does the work. It reports
// whether this call ended a confirmed dialog.
func (d *dialog) end() bool {
	t := d.tab
	t.mu.Lock()
	if d.state == dialogEnded {
		t.mu.Unlock()
		return false
	}
	wasUp := d.state == dialogConfirmed
	d.state = dialogEnded
	d.inFlight = nil
	sess := d.media
	t.removeLocked(d)
	t.mu.Unlock()

	if sess == nil {
		return wasUp
	}
	st := sess.Stats()
	webrtc := sess.IsWebRTC()
	_ = sess.Close()
	if !wasUp {
		// An INVITE that never connected: nothing was ever counted as
		// started, so nothing is counted as ended.
		return false
	}
	t.metrics.DialogEnded()
	t.metrics.MediaEnded(webrtc, st)
	t.log.Info("call ended", "sip_call_id", d.callID, "stats", st)
	return true
}
