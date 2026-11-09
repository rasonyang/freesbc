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

// sipgoUpgradeFailMsg is the message sipgo v1.6.0 logs, at Error with the
// gobwas/ws handshake error as "error", when an accepted WS or WSS
// connection's request is not a WebSocket upgrade (TransportWS.Serve, sipgo
// sip/transport_ws.go). Any host that can reach the listener can trigger it,
// so it is rewritten like a parse failure; TestSipgoUpgradeFailureLogContract
// fails if a sipgo upgrade changes the string, the level or the attribute
// names.
const sipgoUpgradeFailMsg = "Fail to upgrade"

// parseFailWarnEvery is the minimum gap between two WARN lines about parse
// failures. Every failure is counted and logged at Debug; only the WARN is
// rate-limited.
const parseFailWarnEvery = time.Minute

// parseFailState is shared by every derived copy of one sipgoHandler: the
// WARN dedupe is global, because sipgo's record does not carry the source
// address. A handler holds one for parse failures and one for upgrade
// failures, so each has its own WARN.
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
// parseFailWarnEvery summarises what was suppressed. A failed WS/WSS upgrade
// is treated the same way (Debug, freesbc_sip_upgrade_failures_total, its own
// WARN). Every other record passes through untouched.
type sipgoHandler struct {
	inner     slog.Handler
	st        *parseFailState // parse failures
	up        *parseFailState // WS/WSS upgrade failures
	transport string          // from the "caller" attr sipgo's per-transport logger adds
}

// newSipgoHandler wraps inner. parseCount is called once per parse failure
// and upgradeCount once per failed WS/WSS upgrade, each with the transport
// label ("UDP", "WS", ...; metricOther when it cannot be told).
func newSipgoHandler(inner slog.Handler, parseCount, upgradeCount func(transport string)) *sipgoHandler {
	return &sipgoHandler{
		inner: inner,
		st:    &parseFailState{count: parseCount, now: time.Now},
		up:    &parseFailState{count: upgradeCount, now: time.Now},
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
		return h.handleParseFail(ctx, r)
	case sipgoUpgradeFailMsg:
		return h.handleUpgradeFail(ctx, r)
	}
	return h.inner.Handle(ctx, r)
}

// recordTransport is the metric label for a record from this logger.
func (h *sipgoHandler) recordTransport() string {
	if h.transport == "" {
		return metricOther
	}
	return h.transport
}

func (h *sipgoHandler) handleParseFail(ctx context.Context, r slog.Record) error {
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
	transport := h.recordTransport()
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

// handleUpgradeFail rewrites sipgo's "Fail to upgrade". The error is
// gobwas/ws's fixed handshake reason or an I/O error from reading the request
// or writing the 400; neither carries request bytes, so it is kept. Any other
// attribute (there is none in v1.6.0) is dropped rather than forwarded.
func (h *sipgoHandler) handleUpgradeFail(ctx context.Context, r slog.Record) error {
	var cause slog.Value
	var hasCause bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "error" {
			cause, hasCause = a.Value, true
		}
		return true
	})
	transport := h.recordTransport()
	h.up.count(transport)

	attrs := []slog.Attr{slog.String("transport", transport)}
	if hasCause {
		attrs = append(attrs, slog.Attr{Key: "error", Value: cause})
	}
	rec := slog.NewRecord(r.Time, slog.LevelDebug, "websocket upgrade failed; connection closed", r.PC)
	rec.AddAttrs(attrs...)
	var err error
	if h.inner.Enabled(ctx, slog.LevelDebug) {
		err = h.inner.Handle(ctx, rec)
	}

	if n, ok := h.up.takeWarn(); ok && h.inner.Enabled(ctx, slog.LevelWarn) {
		w := slog.NewRecord(r.Time, slog.LevelWarn,
			"websocket upgrade failures: non-WebSocket requests closed on a public listener", r.PC)
		w.AddAttrs(attrs...)
		w.AddAttrs(slog.Int("suppressed", n), slog.Duration("interval", parseFailWarnEvery))
		if werr := h.inner.Handle(ctx, w); err == nil {
			err = werr
		}
	}
	return err
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
