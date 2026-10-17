package edge

import (
	"sync"

	"github.com/emiago/sipgo/sip"
)

// provTable works around a sipgo v1.6.0 race that loses provisional
// responses (re-check when upgrading sipgo; v1.4.3, v1.5.0 and v1.6.0 all have it). Upstream:
// emiago/sipgo#306, with fixes proposed in #307 and #354, none merged.
//
// TransactionLayer.handleMessage starts one goroutine per response, so a
// 180 or 183 read just before a 200 can reach the INVITE client
// transaction after it. The transaction is then Accepted (or Completed),
// drops the 1xx (RFC 6026 §7.2) and Responses() never carries it, though
// on the wire it came first. The transport layer's OnMessage handlers run
// synchronously in the read goroutine, in wire order, but AFTER the
// transaction layer's own handler (registered first) has started that
// response's goroutine; the *sip.Response they see is the same pointer the
// transaction later hands to Responses(). So when pumpInvite reads a final,
// observe may not have recorded it yet. provTable records, per
// registered INVITE client transaction, the INVITE responses in that
// order; pumpInvite replays the recorded provisionals that precede a final
// response and that it has not relayed (invite_leg.go).
//
// sipgo puts a response on Responses() while holding the transaction's FSM
// lock, so the channel order is the FSM order: a 1xx the FSM accepted
// before the final is always read from the channel before it, never after.
// A provisional that is recorded but missing from the channel is one the
// FSM dropped, which is exactly what replay recovers.
//
// Not covered: provisionals on in-dialog (re-INVITE) transactions and
// forked 2xx after the first (watch2xx), which are not relayed through
// pumpInvite.
type provTable struct {
	mu   sync.Mutex // leaf: held for a map lookup and a short append only
	recs map[string]*provRec
}

// provCap bounds the responses kept per transaction (the oldest go first).
const provCap = 32

type provRec struct {
	seq  uint64
	resp []provEntry
}

type provEntry struct {
	seq uint64
	res *sip.Response
}

// register starts recording the responses of the INVITE client transaction
// out is about to start, and returns the function that stops it. Call it
// before the request is sent. A request with no usable key records nothing.
func (t *provTable) register(out *sip.Request) (release func()) {
	key, err := sip.ClientTxKeyMake(out)
	if err != nil {
		return func() {}
	}
	t.mu.Lock()
	if t.recs == nil {
		t.recs = make(map[string]*provRec)
	}
	t.recs[key] = &provRec{}
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		delete(t.recs, key)
		t.mu.Unlock()
	}
}

// observe is the transport-layer message handler: it must stay short and
// must never block.
func (t *provTable) observe(m sip.Message) {
	res, ok := m.(*sip.Response)
	if !ok || res.StatusCode == 100 {
		return
	}
	if cs := res.CSeq(); cs == nil || cs.MethodName != sip.INVITE {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.recs) == 0 {
		return
	}
	key, err := sip.ClientTxKeyMake(res)
	if err != nil {
		return
	}
	rec := t.recs[key]
	if rec == nil {
		return
	}
	rec.seq++
	if len(rec.resp) >= provCap {
		copy(rec.resp, rec.resp[1:])
		rec.resp = rec.resp[:len(rec.resp)-1]
	}
	rec.resp = append(rec.resp, provEntry{seq: rec.seq, res: res})
}

// before returns the provisional responses recorded for out's transaction
// that were read ahead of final, in wire order, and that are not in done.
// When final is not recorded yet, observe has not finished with it, so
// nothing read after it can be recorded either (one read loop per
// transport connection): every recorded unrelayed provisional precedes it.
func (t *provTable) before(out *sip.Request, final *sip.Response, done map[*sip.Response]struct{}) []*sip.Response {
	key, err := sip.ClientTxKeyMake(out)
	if err != nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.recs[key]
	if rec == nil {
		return nil
	}
	var fseq uint64
	for _, e := range rec.resp {
		if e.res == final {
			fseq = e.seq
			break
		}
	}
	if fseq == 0 {
		fseq = ^uint64(0) // not recorded yet: everything recorded came first
	}
	var out1 []*sip.Response
	for _, e := range rec.resp {
		if e.seq >= fseq {
			break
		}
		if e.res.StatusCode >= 200 {
			continue
		}
		if _, ok := done[e.res]; ok {
			continue
		}
		out1 = append(out1, e.res)
	}
	return out1
}
