package edge

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// redactHandler wraps the edge's slog.Handler so SDES key material cannot
// reach a log by any route. FreeSBC never logs a message body, and the
// sdp package's errors never quote a crypto line; this is the backstop for
// the rest (a library error that echoes a rejected line, a sipgo record
// that carries a message, a future debug line): every string attribute and
// the message itself pass through sdp.RedactCrypto, which turns
// "inline:<key>" into "inline:[redacted]".
type redactHandler struct{ inner slog.Handler }

func newRedactHandler(inner slog.Handler) slog.Handler { return &redactHandler{inner: inner} }

func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{inner: h.inner.WithGroup(name)}
}

func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a)
	}
	return &redactHandler{inner: h.inner.WithAttrs(out)}
}

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	rec := slog.NewRecord(r.Time, r.Level, sdp.RedactCrypto(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		rec.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, rec)
}

// redactAttr redacts one attribute. A value that is neither a string, an
// error nor a Stringer is left alone: those kinds cannot carry SDP text.
func redactAttr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, sdp.RedactCrypto(v.String()))
	case slog.KindGroup:
		g := v.Group()
		out := make([]slog.Attr, len(g))
		for i, x := range g {
			out[i] = redactAttr(x)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	case slog.KindAny:
		switch x := v.Any().(type) {
		case error, fmt.Stringer:
			// fmt.Sprint recovers from a panicking or nil receiver.
			if s := fmt.Sprint(x); sdp.RedactCrypto(s) != s {
				return slog.String(a.Key, sdp.RedactCrypto(s))
			}
		}
	}
	return a
}
