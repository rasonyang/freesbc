package edge

import (
	"github.com/emiago/sipgo/sip"
)

// Server transactions without a parked goroutine (issue #170).
//
// sipgo v1.4.3 runs every new server transaction's handler on its own
// goroutine (TransactionLayer.handleMessage, transaction_layer.go:140), and
// its Server.handleRequest (server.go:258) then calls
// ServerTx.TerminateGracefully (transaction_server_tx.go:165). On UDP, once
// a final response has gone out, that waits on <-tx.Done() (line 181)
// until the transaction's own timer ends it: Timer J for a non-INVITE,
// Timer L after a 2xx to an INVITE, Timer H or I after a non-2xx (64*T1 =
// 32 s, or T4 = 5 s after the ACK). The wait does nothing: the timers are
// time.AfterFunc callbacks that delete the transaction on their own, and
// retransmissions are absorbed by the transaction layer, which finds the
// transaction in its store and replays the last response on a fresh
// goroutine (serverTxRequest, transaction_layer.go:228). The parked
// goroutine only keeps its stack, grown by the handler, for 32 s: about one
// goroutine and 4 KiB of stack per transaction, which at a few thousand
// requests per second is hundreds of thousands of goroutines.
//
// So the edge installs its own transaction-layer request handler in place
// of sipgo's Server.handleRequest. It dispatches by method exactly as
// sipgo's Server does and then releases the transaction:
//
//   - a final response went out through the handler's transaction (the
//     finalTracker saw it) on an unreliable transport: return at once and
//     let sipgo's timers end the transaction, as they already did;
//   - anything else (no final, or tcp/tls/ws/wss): call TerminateGracefully
//     as sipgo does. Without a final it is Terminate (and the silent drop of
//     onInvite depends on exactly that); on a reliable transport it is
//     Terminate too. The one case where it still blocks is a final that
//     sipgo itself sent behind the handler's back, the 487 to a CANCEL;
//     that is rare and keeps sipgo's behaviour unchanged.
//
// Nothing about the transaction's state machine, timers, retransmission
// handling or lifetime changes; only the goroutine stops waiting for it.
// Re-check when upgrading sipgo: this relies on Server.handleRequest doing
// nothing but run the request middlewares (the edge registers none),
// dispatch by method and TerminateGracefully, and on TransactionLayer.
// OnRequest replacing the handler NewServer installed.

// routes maps a method to its guarded handler; noRoute takes the rest.
type routes struct {
	byMethod map[sip.RequestMethod]func(*sip.Request, sip.ServerTransaction)
	noRoute  func(*sip.Request, sip.ServerTransaction)
}

// serveTx is the transaction layer's request handler (see above).
func (s *Server) serveTx(req *sip.Request, stx *sip.ServerTx) {
	h, ok := s.routes.byMethod[req.Method]
	if !ok {
		h = s.routes.noRoute
	}
	if stx == nil {
		// sipgo never passes a nil transaction to its handler today; a
		// typed nil must not reach the handlers as a non-nil interface.
		return
	}
	// Decided before the handler runs: it may rewrite the request's
	// transport while building what it forwards. sipgo's ServerTx decides
	// reliability the same way, from its origin request at creation.
	reliable := sip.IsReliable(req.Transport())
	tx := &finalTracker{ServerTransaction: stx}
	h(req, tx)
	if !reliable && tx.finalised.Load() {
		return
	}
	stx.TerminateGracefully()
}
