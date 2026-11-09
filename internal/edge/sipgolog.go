package edge

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

// sipgoParseFailMsg is the message sipgo v1.6.0 logs, at Error and with the
// whole raw message as the "data" attribute, when its parser rejects a read
// (sip/transport_udp.go, transport_tcp.go, transport_ws.go). The handler
// below keys on it; TestSipgoParseFailureLogContract fails if a sipgo
// upgrade changes the string, the level or the attribute names.
const sipgoParseFailMsg = "failed to parse"

// sipgoUpgradeFailMsg is the message sipgo v1.6.0 logs at Error when an
// accepted ws/wss connection's first request is not a valid WebSocket
// upgrade (sip/transport_ws.go, TransportWS.Serve), right before it closes
// the connection. Any host can write it on ws, and any host that completes the TLS
// handshake on wss.
// TestSipgoUpgradeFailureLogContract fails if a sipgo upgrade changes the
// string, the level or the attribute names.
const sipgoUpgradeFailMsg = "Fail to upgrade"

// sipgoUpgradeCloseFailMsg is the Error sipgo logs when closing the connection
// after a failed upgrade fails (the same function, right after
// sipgoUpgradeFailMsg). On wss a peer that resets after its request makes
// tls.Conn.Close return the failed close_notify, so a remote peer can drive it.
const sipgoUpgradeCloseFailMsg = "Closing connection failed"

// sipgoWSHeaderMsg is the Debug record sipgo logs per request header of a
// ws/wss upgrade when sip.SIPDebug is on (the HEP mirror sets it), with the
// header name as the attribute key and its value as the attribute value.
// The headers are attacker-controlled, so the record is dropped.
const sipgoWSHeaderMsg = "non-websocket header:"

// parseFailWarnEvery is the minimum gap between two WARN lines about parse
// failures, and likewise about upgrade failures. Every failure is counted and
// logged at Debug; only the WARN is rate-limited.
const parseFailWarnEvery = time.Minute

// parseFailState is shared by every derived copy of one sipgoHandler: the
// WARN dedupe is global, because sipgo's record does not carry the source
// address.
type parseFailState struct {
	count func(transport string)
	now   func() time.Time

	mu         sync.Mutex
	lastWarn   time.Time
	suppressed int
}

// sipgoHandler wraps the slog.Handler handed to sipgo. A message the sipgo
// parser rejected is attacker-controlled bytes from a public socket (it can
// include an Authorization header), so the record is rewritten before it
// reaches the real handler: the "data" attribute is replaced by its length,
// the record drops from Error to Debug, the failure is counted
// (freesbc_sip_parse_failures_total) and at most one WARN per
// parseFailWarnEvery summarises what was suppressed. Every other record
// passes through untouched.
type sipgoHandler struct {
	inner     slog.Handler
	st        *parseFailState
	upgrade   *parseFailState // same shape, own WARN budget, for failed WS upgrades
	transport string          // from the "caller" attr sipgo's per-transport logger adds
}

// newSipgoHandler wraps inner. count is called once per parse failure and
// countUpgrade once per failed WebSocket upgrade, with the transport label
// ("UDP", "WS", ...; metricOther when it cannot be told).
func newSipgoHandler(inner slog.Handler, count, countUpgrade func(transport string)) *sipgoHandler {
	return &sipgoHandler{
		inner:   inner,
		st:      &parseFailState{count: count, now: time.Now},
		upgrade: &parseFailState{count: countUpgrade, now: time.Now},
	}
}

func (h *sipgoHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *sipgoHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.inner = h.inner.WithGroup(name)
	return &c
}

// WithAttrs learns the transport from sipgo's per-transport logger
// (log.With("caller", "Transport<UDP>")) and refuses to forward a "data"
// attribute: the one attribute sipgo uses for raw bytes must not be able to
// reach the real handler by way of a derived logger either.
func (h *sipgoHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	kept := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if a.Key == "data" {
			continue
		}
		if a.Key == "caller" {
			if t, ok := transportFromCaller(a.Value.String()); ok {
				c.transport = t
			}
		}
		kept = append(kept, a)
	}
	c.inner = h.inner.WithAttrs(kept)
	return &c
}

// transportFromCaller maps sipgo's "Transport<UDP>" logger name onto a
// bounded metric label.
func transportFromCaller(caller string) (string, bool) {
	name, ok := strings.CutPrefix(caller, "Transport<")
	if !ok {
		return "", false
	}
	name, ok = strings.CutSuffix(name, ">")
	if !ok {
		return "", false
	}
	if i := transportIndex(name); i < len(metricTransports) {
		return metricTransports[i], true
	}
	return metricOther, true
}

func (h *sipgoHandler) Handle(ctx context.Context, r slog.Record) error {
	switch r.Message {
	case sipgoParseFailMsg:
	case sipgoUpgradeFailMsg:
		return h.handleUpgradeFail(ctx, r)
	case sipgoUpgradeCloseFailMsg:
		return h.handleUpgradeCloseFail(ctx, r)
	case sipgoWSHeaderMsg:
		return nil
	default:
		return h.inner.Handle(ctx, r)
	}
	var size int
	var cause error
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "data":
			size = len(a.Value.String())
		case "error":
			if err, ok := a.Value.Any().(error); ok {
				cause = err
			}
		}
		return true
	})
	transport := h.transport
	if transport == "" {
		transport = metricOther
	}
	h.st.count(transport)
	reason := parseFailReason(cause)

	// The parser's error text is not logged either: sipgo builds it from the
	// message it rejected (the start line, a header value), so it can carry
	// the same secrets. Only the reason class and the length are.
	rec := slog.NewRecord(r.Time, slog.LevelDebug, "sip parse failed; message dropped", r.PC)
	rec.AddAttrs(slog.String("transport", transport), slog.Int("len", size), slog.String("reason", reason))
	var err error
	if h.inner.Enabled(ctx, slog.LevelDebug) {
		err = h.inner.Handle(ctx, rec)
	}

	if n, ok := h.st.takeWarn(); ok && h.inner.Enabled(ctx, slog.LevelWarn) {
		w := slog.NewRecord(r.Time, slog.LevelWarn,
			"sip parse failures: unparsable messages dropped on a public listener; payloads are never logged", r.PC)
		w.AddAttrs(slog.String("transport", transport), slog.Int("len", size),
			slog.String("reason", reason), slog.Int("suppressed", n),
			slog.Duration("interval", parseFailWarnEvery))
		if werr := h.inner.Handle(ctx, w); err == nil {
			err = werr
		}
	}
	return err
}

// handleUpgradeFail rewrites sipgo's failed-upgrade record: Debug, counted,
// and at most one WARN per parseFailWarnEvery. The error is gobwas/ws's
// fixed reason or an I/O error (readLine, the 400-response flush), never
// request bytes; the request itself is never part of sipgo's record.
func (h *sipgoHandler) handleUpgradeFail(ctx context.Context, r slog.Record) error {
	var cause any = "unknown"
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "error" {
			cause = a.Value.Any()
		}
		return true
	})
	transport := h.transport
	if transport == "" {
		transport = metricOther
	}
	h.upgrade.count(transport)

	rec := slog.NewRecord(r.Time, slog.LevelDebug, "websocket upgrade failed; connection closed", r.PC)
	rec.AddAttrs(slog.String("transport", transport), slog.Any("error", cause))
	var err error
	if h.inner.Enabled(ctx, slog.LevelDebug) {
		err = h.inner.Handle(ctx, rec)
	}
	if n, ok := h.upgrade.takeWarn(); ok && h.inner.Enabled(ctx, slog.LevelWarn) {
		w := slog.NewRecord(r.Time, slog.LevelWarn,
			"websocket upgrade failures: non-upgrade requests closed on a public listener; requests are never logged", r.PC)
		w.AddAttrs(slog.String("transport", transport), slog.Any("error", cause),
			slog.Int("suppressed", n), slog.Duration("interval", parseFailWarnEvery))
		if werr := h.inner.Handle(ctx, w); err == nil {
			err = werr
		}
	}
	return err
}

// handleUpgradeCloseFail rewrites the close failure that follows a failed
// upgrade to Debug. It adds no count and no WARN: the failure before it
// already earned both.
func (h *sipgoHandler) handleUpgradeCloseFail(ctx context.Context, r slog.Record) error {
	if !h.inner.Enabled(ctx, slog.LevelDebug) {
		return nil
	}
	var cause any = "unknown"
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "error" {
			cause = a.Value.Any()
		}
		return true
	})
	transport := h.transport
	if transport == "" {
		transport = metricOther
	}
	rec := slog.NewRecord(r.Time, slog.LevelDebug, "websocket upgrade failed; closing the connection also failed", r.PC)
	rec.AddAttrs(slog.String("transport", transport), slog.Any("error", cause))
	return h.inner.Handle(ctx, rec)
}

// takeWarn reports whether this failure is the one that earns a WARN, and
// how many failures were folded into the interval since the last one.
func (st *parseFailState) takeWarn() (suppressed int, ok bool) {
	now := st.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.lastWarn.IsZero() && now.Sub(st.lastWarn) < parseFailWarnEvery {
		st.suppressed++
		return 0, false
	}
	n := st.suppressed
	st.lastWarn, st.suppressed = now, 0
	return n, true
}

// parseFailReason names the parse error without echoing it.
func parseFailReason(err error) string {
	switch {
	case err == nil:
		return "unknown"
	case errors.Is(err, sip.ErrParseLineNoCRLF), errors.Is(err, sip.ErrParseEOF),
		errors.Is(err, sip.ErrParseSipPartial), errors.Is(err, sip.ErrParseReadBodyIncomplete):
		return "incomplete"
	case errors.Is(err, sip.ErrMessageTooLarge):
		return "too_large"
	}
	return "malformed"
}
