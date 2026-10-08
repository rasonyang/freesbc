package edge

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// SUBSCRIBE (RFC 6665) creates a dialog of its own, separate from any
// INVITE dialog: the subscriber's SUBSCRIBE and the notifier's NOTIFYs
// share a Call-ID and a pair of tags, and the NOTIFYs arrive on the plane
// the SUBSCRIBE did not. FreeSBC stays on that path with the same double
// Record-Route as a call and keeps one small record per subscription
// (subTable) so a NOTIFY is matched, by Call-ID and both tags, to a
// subscription it carried and nothing else. Without the record a public
// NOTIFY with a made-up To tag would reach the switch past admission.
//
// What a record costs is bounded: maxSubsPerBinding per registration
// binding and maxSubscriptions in all. A SUBSCRIBE over either cap is
// answered 503 with Retry-After (subCapRetryAfter) before anything is
// forwarded. Records end on a terminated NOTIFY, a 481 to either request,
// the removal of the registration binding the subscription belongs to
// (un-REGISTER, WebSocket close, expiry), or their own deadline.

const (
	// maxSubsPerBinding caps the subscription records one registration
	// binding may hold, so one client cannot fill the table.
	maxSubsPerBinding = 32

	// maxSubscriptions caps the records in all. It is the registration
	// table's size: a table that could outgrow the clients that feed it
	// would be the only unbounded thing in the proxy.
	maxSubscriptions = defaultMaxBindings

	// subExpiryMargin is how long a record outlives the expiry the
	// notifier granted. The notifier's final NOTIFY (Subscription-State:
	// terminated) follows the expiry, and a 2xx with Expires: 0 means the
	// subscription is over but that NOTIFY still has to route (RFC 6665
	// §4.4.1), so such a record is kept for this margin and not deleted.
	subExpiryMargin = 32 * time.Second

	// subCapRetryAfter is the Retry-After (seconds) of the 503 a
	// SUBSCRIBE over a cap gets.
	subCapRetryAfter = 30

	// subDefaultExpires stands in for an Expires header neither the 2xx
	// nor the SUBSCRIBE carries.
	subDefaultExpires = time.Hour

	// subCapWarnEvery spaces the WARN logged for a cap reject.
	subCapWarnEvery = 30 * time.Second
)

// subState is whether a subscription's SUBSCRIBE has been answered.
type subState int

const (
	// subPending: the SUBSCRIBE is in flight. The notifier's tag is not
	// known yet; a NOTIFY may beat the 2xx and name it first.
	subPending subState = iota
	// subActive: a 2xx confirmed it.
	subActive
)

// subscription is the record of one SUBSCRIBE dialog. Every field is
// guarded by subTable.mu; readers get a copy from lookup.
type subscription struct {
	callID string
	// subTag is the SUBSCRIBE's From tag, notTag the notifier's (the To
	// tag of the 2xx). notTag is empty while the record is pending.
	subTag, notTag string
	event          string
	// token is the registration binding the subscription is charged to.
	token string
	// subscriberPlane is the plane the SUBSCRIBE came from: public for a
	// client's, private for a switch-initiated one.
	subscriberPlane plane
	// route is where each end is reached and the Contact it gave
	// (publicRemote and privateRemote are known from the first request).
	route    dialogRoute
	deadline time.Time
	state    subState
	ended    bool
}

// subTable holds the subscription records. Lock order: Location.mu is
// never held when subTable.mu is taken (Location hands removed tokens to
// dropTokens only after it unlocks), and subTable.mu is a leaf: nothing
// else is locked under it except the metrics gauge, which is atomic.
type subTable struct {
	mu       sync.Mutex
	byCallID map[string][]*subscription
	byToken  map[string][]*subscription
	total    int
	max      int
	maxPer   int
	closed   bool
	metrics  *Metrics
}

func newSubTable(m *Metrics) *subTable {
	return &subTable{
		byCallID: map[string][]*subscription{},
		byToken:  map[string][]*subscription{},
		max:      maxSubscriptions,
		maxPer:   maxSubsPerBinding,
		metrics:  m,
	}
}

// subBegin is the outcome of subTable.begin.
type subBegin int

const (
	subBeginOK subBegin = iota
	subBeginFull
	subBeginPerBindingFull
	subBeginClosed
)

// begin adds a pending record, enforcing both caps atomically with the
// insertion.
func (t *subTable) begin(callID, subTag, event, token string, subscriber plane, route dialogRoute, now time.Time) (*subscription, subBegin) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.closed:
		return nil, subBeginClosed
	case t.total >= t.max:
		return nil, subBeginFull
	case len(t.byToken[token]) >= t.maxPer:
		return nil, subBeginPerBindingFull
	}
	sub := &subscription{
		callID: callID, subTag: subTag, event: event, token: token,
		subscriberPlane: subscriber, route: route,
		deadline: now.Add(2 * subExpiryMargin),
		state:    subPending,
	}
	t.byCallID[callID] = append(t.byCallID[callID], sub)
	t.byToken[token] = append(t.byToken[token], sub)
	t.total++
	t.metrics.SetSubscriptions(t.total)
	return sub, subBeginOK
}

// confirm makes a pending record active once its 2xx is relayed: it learns
// the notifier's tag and Contact, and lives for the granted expiry plus
// subExpiryMargin. An Expires of zero keeps the record for the margin
// alone. It reports false when the record is gone (the table was closed or
// the binding removed meanwhile).
func (t *subTable) confirm(sub *subscription, notTag string, notifierContact sip.Uri, plane plane, expires time.Duration, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if sub.ended || notTag == "" {
		return false
	}
	sub.notTag = notTag
	if notifierContact.Host != "" {
		if plane == planePublic {
			sub.route.publicContact = notifierContact
		} else {
			sub.route.privateContact = notifierContact
		}
	}
	sub.state = subActive
	sub.deadline = now.Add(expires + subExpiryMargin)
	return true
}

// lookup finds the subscription a request names by Call-ID and both tags
// and says which end sent it; arrived is the plane the request came in on,
// which must be that end's plane. A NOTIFY from the notifier that names
// the subscriber's tag matches a record still pending (it can beat the
// relayed 2xx) and teaches it the notifier's tag. v is a copy of the
// record for the caller to read without the lock.
//
// The method must suit the end that sent it: a NOTIFY comes only from the
// notifier and a SUBSCRIBE only from the subscriber. A request from the
// wrong end (a subscriber sending NOTIFYs into its own subscription, a
// notifier "refreshing" it) matches nothing, so the caller answers 481.
// onSubscribe and the NOTIFY path are its only callers.
func (t *subTable) lookup(callID, fromTag, toTag string, arrived plane, method sip.RequestMethod) (sub *subscription, v subscription, fromSubscriber, ok bool) {
	if fromTag == "" || toTag == "" {
		return nil, subscription{}, false, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.byCallID[callID] {
		switch {
		case c.state == subActive && c.subTag == fromTag && c.notTag == toTag && arrived == c.subscriberPlane:
			if method == sip.NOTIFY {
				continue
			}
			return c, *c, true, true
		case c.state == subActive && c.notTag == fromTag && c.subTag == toTag && arrived != c.subscriberPlane:
			if method == sip.SUBSCRIBE {
				continue
			}
			return c, *c, false, true
		case c.state == subPending && c.subTag == toTag && arrived != c.subscriberPlane &&
			(c.notTag == "" || c.notTag == fromTag):
			if method == sip.SUBSCRIBE {
				continue
			}
			c.notTag = fromTag
			return c, *c, false, true
		}
	}
	return nil, subscription{}, false, false
}

// notePublicRemote follows a NAT remap: src is the source a request from
// the public end of the subscription just arrived from, and later requests
// toward that end go there.
func (t *subTable) notePublicRemote(sub *subscription, src string) {
	if src == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !sub.ended {
		sub.route.publicRemote = src
	}
}

// learnContact records a pending record's notifier Contact from the NOTIFY
// that beat the 2xx, when the record has none yet.
func (t *subTable) learnContact(sub *subscription, u sip.Uri) {
	if u.Host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if sub.ended {
		return
	}
	if sub.subscriberPlane == planePublic {
		if sub.route.privateContact.Host == "" {
			sub.route.privateContact = u
		}
	} else if sub.route.publicContact.Host == "" {
		sub.route.publicContact = u
	}
}

// refresh moves a record's deadline to expires from now plus
// subExpiryMargin (a refresh answered 2xx, or a NOTIFY's
// Subscription-State expires).
func (t *subTable) refresh(sub *subscription, expires time.Duration, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !sub.ended {
		sub.deadline = now.Add(expires + subExpiryMargin)
	}
}

// end removes a record. It is idempotent.
func (t *subTable) end(sub *subscription) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endLocked(sub)
}

func (t *subTable) endLocked(sub *subscription) {
	if sub.ended {
		return
	}
	sub.ended = true
	t.byCallID[sub.callID] = removeSub(t.byCallID[sub.callID], sub)
	if len(t.byCallID[sub.callID]) == 0 {
		delete(t.byCallID, sub.callID)
	}
	t.byToken[sub.token] = removeSub(t.byToken[sub.token], sub)
	if len(t.byToken[sub.token]) == 0 {
		delete(t.byToken, sub.token)
	}
	t.total--
	t.metrics.SetSubscriptions(t.total)
}

func removeSub(list []*subscription, sub *subscription) []*subscription {
	for i, e := range list {
		if e == sub {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// dropTokens ends every record charged to one of the removed registration
// bindings (the Location removal hook).
func (t *subTable) dropTokens(tokens []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tok := range tokens {
		for _, sub := range append([]*subscription(nil), t.byToken[tok]...) {
			t.endLocked(sub)
		}
	}
}

// prune ends the records whose deadline has passed and returns how many.
func (t *subTable) prune(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, list := range t.byCallID {
		for _, sub := range append([]*subscription(nil), list...) {
			if !now.Before(sub.deadline) {
				t.endLocked(sub)
				n++
			}
		}
	}
	return n
}

// close stops begin from admitting records (shutdown).
func (t *subTable) close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
}

// closeAll ends every record.
func (t *subTable) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for _, list := range t.byCallID {
		for _, sub := range append([]*subscription(nil), list...) {
			t.endLocked(sub)
		}
	}
}

// count is the number of records.
func (t *subTable) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

// subCapWarner rate-limits the WARN of a subscription cap reject.
type subCapWarner struct {
	mu   sync.Mutex
	last [2]time.Time // per scope: 0 total, 1 per binding
}

func (w *subCapWarner) allow(scope int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now := time.Now(); now.Sub(w.last[scope]) >= subCapWarnEvery {
		w.last[scope] = now
		return true
	}
	return false
}

// onSubscribe proxies a SUBSCRIBE.
//
//   - A public out-of-dialog SUBSCRIBE must pass admitPublicOutOfDialog
//     (a live registration at the source; silent drop and
//     subscribe_not_admitted otherwise, 405 from a carrier). It goes to the
//     switch node hashed from the subscriber, with FreeSBC's own Contact and
//     the double Record-Route, so the NOTIFYs come back through the proxy.
//   - A SUBSCRIBE from the switch with no To tag is classified by its
//     Request-URI like any switch request: a client token delivers it to
//     that client, a carrier is 405, anything else 404.
//   - A SUBSCRIBE with a To tag is a refresh or an unsubscribe and must
//     match a record; else 481.
func (s *Server) onSubscribe(req *sip.Request, tx sip.ServerTransaction, in inbound) {
	if fsip.ToTag(req) != "" {
		arrived := planePublic
		if in.private() {
			arrived = planePrivate
		}
		sub, v, fromSub, ok := s.subs.lookup(fsip.CallID(req), fsip.FromTag(req), fsip.ToTag(req), arrived, req.Method)
		if !ok {
			s.reject(req, tx, 481, "Subscription Does Not Exist")
			return
		}
		s.forwardInSubscription(req, tx, sub, v, fromSub)
		return
	}
	if in.private() {
		s.subscribeToClient(req, tx)
		return
	}
	b, verdict := s.admitPublicOutOfDialog(req, in.src, dropSubscribeNotAdmitted)
	switch verdict {
	case oodDropped:
		return
	case oodCarrier:
		s.respond(req, tx, methodNotAllowed(req))
		return
	}
	event := eventOf(req)
	if event == "" {
		s.reject(req, tx, 489, "Bad Event")
		return
	}
	pub, ok := s.publicSideFor(req)
	name, entry, found := s.selectUpstream(hashUserFor(req))
	if !ok || !found {
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	route := dialogRoute{transport: pub.transport, publicRemote: req.Source(), privateRemote: entry.host}
	if u, ok := fsip.ContactURI(req); ok {
		route.publicContact = u
	}
	sub, ok := s.beginSubscription(req, tx, event, b.Token, planePublic, route, 480, "Temporarily Unavailable")
	if !ok {
		return
	}
	out, err := s.prepareForward(req, pub, s.topo.private, entry.host, true)
	if err != nil {
		s.subs.end(sub)
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	fsip.SetContact(out, s.topo.private.uri())
	s.log.Debug("proxying SUBSCRIBE to switch", "sip_call_id", fsip.CallID(req),
		"event", event, "upstream", name, "aor", b.AOR)
	s.relaySubscribe(req, tx, out, sub, pub, planePrivate)
}

// subscribeToClient handles a SUBSCRIBE from the switch that names a
// client by its fsbc= token and delivers it there.
func (s *Server) subscribeToClient(req *sip.Request, tx sip.ServerTransaction) {
	switch kind, _ := s.classifySwitchRequest(req); kind {
	case targetClient:
	case targetCarrier:
		s.respond(req, tx, methodNotAllowed(req))
		return
	default:
		s.reject(req, tx, 404, "Not Found")
		return
	}
	b, ok := s.bindingForRequest(req)
	if !ok {
		s.reject(req, tx, 404, "Not Found")
		return
	}
	to, ok := s.topo.publicSide(b.Transport)
	if !ok {
		s.reject(req, tx, 480, "Temporarily Unavailable")
		return
	}
	event := eventOf(req)
	if event == "" {
		s.reject(req, tx, 489, "Bad Event")
		return
	}
	route := dialogRoute{transport: b.Transport, publicRemote: b.Source.String(), privateRemote: req.Source()}
	if u, ok := fsip.ContactURI(req); ok {
		route.privateContact = u
	}
	sub, ok := s.beginSubscription(req, tx, event, b.Token, planePrivate, route, 404, "Not Found")
	if !ok {
		return
	}
	out, err := s.prepareForward(req, s.topo.private, to, b.Source.String(), true)
	if err != nil {
		s.subs.end(sub)
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	// The Request-URI the switch used names FreeSBC's own contact for the
	// client; the client must see one addressed to itself.
	out.Recipient = clientRequestURI(b)
	fsip.SetContact(out, to.uri())
	s.log.Debug("proxying SUBSCRIBE to client", "sip_call_id", fsip.CallID(req),
		"event", event, "aor", b.AOR, "transport", b.Transport)
	s.relaySubscribe(req, tx, out, sub, s.topo.private, planePublic)
}

// beginSubscription adds the pending record, answering 503 + Retry-After
// itself when a cap or the shutdown refuses it. Cap rejects are logged
// (rate-limited) and are not admission drops: the peer is admitted and told
// to retry.
//
// The binding was read at admission and the record is made here; if the
// binding left the table in between, dropTokens already ran and would never
// see this record, so it would outlive its binding. The binding is checked
// again after the insertion: a removal from now on finds the record, and an
// earlier one is caught here. goneCode is what the requester is told then
// (480 to a public subscriber whose registration lapsed, 404 to the switch,
// whose Request-URI token no longer names anyone).
func (s *Server) beginSubscription(req *sip.Request, tx sip.ServerTransaction, event, token string, subscriber plane, route dialogRoute, goneCode int, goneText string) (*subscription, bool) {
	sub, res := s.subs.begin(fsip.CallID(req), fsip.FromTag(req), event, token, subscriber, route, time.Now())
	switch res {
	case subBeginOK:
		if f := s.afterSubBegin.Load(); f != nil {
			(*f)()
		}
		if _, live := s.loc.ByToken(token); !live {
			s.subs.end(sub)
			s.reject(req, tx, goneCode, goneText)
			return nil, false
		}
		return sub, true
	case subBeginClosed:
		s.reject(req, tx, 503, "Service Unavailable")
		return nil, false
	}
	scope, msg := 0, "subscription table full; refusing SUBSCRIBE"
	if res == subBeginPerBindingFull {
		scope, msg = 1, "too many subscriptions on one registration; refusing SUBSCRIBE"
	}
	args := []any{"sip_call_id", fsip.CallID(req), "retry_after", subCapRetryAfter, "event", event}
	if s.subWarn.allow(scope) {
		s.log.Warn(msg, args...)
	} else {
		s.log.Debug(msg, args...)
	}
	r := sip.NewResponseFromRequest(req, 503, "Service Unavailable", nil)
	r.AppendHeader(sip.NewHeader("Retry-After", strconv.Itoa(subCapRetryAfter)))
	s.respond(req, tx, r)
	return nil, false
}

// relaySubscribe forwards a new SUBSCRIBE and relays its responses.
// requester is the side the SUBSCRIBE came from (its Contact in a 2xx is
// rewritten to name that side); notifierPlane is where the notifier is.
// The 2xx confirms the record before it is relayed, so the subscriber never
// sees a 2xx for a subscription whose NOTIFYs would not route. Anything but
// a 2xx ends the record.
func (s *Server) relaySubscribe(req *sip.Request, tx sip.ServerTransaction, out *sip.Request, sub *subscription, requester side, notifierPlane plane) {
	confirmed := false
	defer func() {
		if !confirmed {
			s.subs.end(sub)
		}
	}()
	adapt := func(res *sip.Response) error {
		if len(res.GetHeaders("Contact")) > 0 {
			fsip.SetContact(res, requester.uri())
		}
		if isSDPBody(res) {
			stripBody(res)
		}
		if res.StatusCode/100 == 2 && !confirmed {
			u, _ := fsip.ContactURI(res)
			confirmed = s.subs.confirm(sub, fsip.ToTag(res), u, notifierPlane, subExpires(res, req), time.Now())
			if !confirmed {
				// Still relayed: a terminated NOTIFY that beat the 2xx
				// already told the subscriber, and a removed binding
				// means the client is gone.
				reason := "record already ended"
				if fsip.ToTag(res) == "" {
					reason = "2xx has no To tag"
				}
				s.log.Debug("SUBSCRIBE 2xx did not confirm the record", "sip_call_id", fsip.CallID(req), "reason", reason)
			}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	if _, err := s.forwardAndRelay(ctx, req, tx, out, respPlain, adapt); err != nil {
		s.log.Debug("forward SUBSCRIBE", "err", err, "sip_call_id", fsip.CallID(req))
		if ctx.Err() != nil {
			s.reject(req, tx, 504, "Server Time-out")
		} else {
			s.reject(req, tx, 503, "Service Unavailable")
		}
	}
}

// forwardInSubscription forwards an in-dialog SUBSCRIBE (refresh or
// unsubscribe) or NOTIFY that matched a record, to the other end of the
// subscription at its stored address, with the Request-URI restored to the
// Contact that end gave. v is the record as lookup saw it; fromSubscriber
// says which end sent the request.
//
// After the final response: a 481 ends the record, a 2xx SUBSCRIBE moves
// its deadline to the granted Expires (zero keeps it for subExpiryMargin
// only), and a 2xx NOTIFY follows its Subscription-State (terminated ends
// the record, expires= moves the deadline). Bodies are not touched, except
// that an SDP body in a response never crosses.
func (s *Server) forwardInSubscription(req *sip.Request, tx sip.ServerTransaction, sub *subscription, v subscription, fromSubscriber bool) {
	senderPublic := (v.subscriberPlane == planePublic) == fromSubscriber
	if senderPublic {
		// The public end's NAT mapping may have changed since the record
		// was made; its latest request shows where it is now.
		if src := req.Source(); src != "" && src != v.route.publicRemote {
			s.subs.notePublicRemote(sub, src)
			v.route.publicRemote = src
		}
	} else if v.subscriberPlane == planePrivate {
		// The client is the notifier and has sent nothing since the
		// SUBSCRIBE, so its binding is the freshest word on where it is: a
		// re-REGISTER from a new source moves it.
		if b, ok := s.loc.ByToken(v.token); ok && b.Transport == v.route.transport {
			if src := b.Source.String(); src != v.route.publicRemote {
				s.subs.notePublicRemote(sub, src)
				v.route.publicRemote = src
			}
		}
	}
	var from, to side
	var dest string
	var contact sip.Uri
	ok := true
	if senderPublic {
		from, ok = s.topo.publicSide(v.route.transport)
		to, dest, contact = s.topo.private, v.route.privateRemote, v.route.privateContact
	} else {
		to, ok = s.topo.publicSide(v.route.transport)
		from, dest, contact = s.topo.private, v.route.publicRemote, v.route.publicContact
	}
	if !ok || dest == "" {
		s.reject(req, tx, 481, "Subscription Does Not Exist")
		return
	}
	if v.state == subPending && req.Method == sip.NOTIFY {
		if u, ok := fsip.ContactURI(req); ok {
			s.subs.learnContact(sub, u)
		}
	}
	out, err := s.prepareForward(req, from, to, dest, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	if contact.Host != "" {
		out.Recipient = contact
	}
	if len(req.GetHeaders("Contact")) > 0 {
		fsip.SetContact(out, to.uri())
	}
	adapt := func(res *sip.Response) error {
		if len(res.GetHeaders("Contact")) > 0 {
			fsip.SetContact(res, from.uri())
		}
		if isSDPBody(res) {
			stripBody(res)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	final, err := s.forwardAndRelay(ctx, req, tx, out, respPlain, adapt)
	if err != nil {
		s.log.Debug("forward in-subscription request", "err", err,
			"method", req.Method.String(), "sip_call_id", fsip.CallID(req))
		if ctx.Err() != nil {
			s.reject(req, tx, 504, "Server Time-out")
		} else {
			s.reject(req, tx, 503, "Service Unavailable")
		}
		return
	}
	switch {
	case final.StatusCode == 481:
		s.subs.end(sub)
	case final.StatusCode/100 != 2:
	case req.Method == sip.SUBSCRIBE:
		s.subs.refresh(sub, subExpires(final, req), time.Now())
	case req.Method == sip.NOTIFY:
		state, exp, hasExp := subscriptionState(req)
		switch {
		case state == "terminated":
			s.subs.end(sub)
		case hasExp:
			s.subs.refresh(sub, exp, time.Now())
		}
	}
}

// eventOf is the request's Event header value (the package token without
// parameters), or "".
func eventOf(req *sip.Request) string {
	h := req.GetHeader("Event")
	if h == nil {
		return ""
	}
	ev, _, _ := strings.Cut(h.Value(), ";")
	return strings.TrimSpace(ev)
}

// subExpires is the lifetime a SUBSCRIBE was granted: the 2xx's Expires,
// else the request's, else an hour.
func subExpires(res *sip.Response, req *sip.Request) time.Duration {
	if h := res.GetHeader("Expires"); h != nil {
		if d, ok := fsip.DeltaSeconds(h.Value()); ok {
			return d
		}
	}
	if h := req.GetHeader("Expires"); h != nil {
		if d, ok := fsip.DeltaSeconds(h.Value()); ok {
			return d
		}
	}
	return subDefaultExpires
}

// subscriptionState parses a NOTIFY's Subscription-State: the lower-cased
// state, and the expires parameter when it has a valid one.
func subscriptionState(req *sip.Request) (state string, expires time.Duration, hasExpires bool) {
	h := req.GetHeader("Subscription-State")
	if h == nil {
		return "", 0, false
	}
	parts := strings.Split(h.Value(), ";")
	state = strings.ToLower(strings.TrimSpace(parts[0]))
	for _, p := range parts[1:] {
		k, val, _ := strings.Cut(strings.TrimSpace(p), "=")
		if strings.EqualFold(strings.TrimSpace(k), "expires") {
			if d, ok := fsip.DeltaSeconds(val); ok {
				return state, d, true
			}
		}
	}
	return state, 0, false
}
