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

// sipgoParseFailMsg is the message sipgo v1.4.3 logs, at Error and with the
// whole raw message as the "data" attribute, when its parser rejects a read
// (sip/transport_udp.go, transport_tcp.go, transport_ws.go). The handler
// below keys on it; TestSipgoParseFailureLogContract fails if a sipgo
// upgrade changes the string, the level or the attribute names.
const sipgoParseFailMsg = "failed to parse"

// parseFailWarnEvery is the minimum gap between two WARN lines about parse
// failures. Every failure is counted and logged at Debug; only the WARN is
// rate-limited.
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
	transport string // from the "caller" attr sipgo's per-transport logger adds
}

// newSipgoHandler wraps inner. count is called once per parse failure with
// the transport label ("UDP", "WS", ...; metricOther when it cannot be told).
func newSipgoHandler(inner slog.Handler, count func(transport string)) *sipgoHandler {
	return &sipgoHandler{
		inner: inner,
		st:    &parseFailState{count: count, now: time.Now},
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
	if r.Message != sipgoParseFailMsg {
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
