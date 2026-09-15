package sip

import "github.com/emiago/sipgo/sip"

// CallID returns a message's Call-ID value, or "" when the message is
// malformed enough to lack one. Every log line that correlates a dialog
// goes through it, so it must never panic on hostile input.
func CallID(msg sip.Message) string {
	if h := msg.CallID(); h != nil {
		return h.Value()
	}
	return ""
}

// FromTag and ToTag read a message's From/To tag, returning "" when the
// header is absent or tagless. They work on both *sip.Request and
// *sip.Response; callers only ever compare the result against a stored
// dialog tag, which is never empty on an established leg, so a missing
// header fails the match rather than nil-dereferencing on malformed input.
func FromTag(msg sip.Message) string {
	if f := msg.From(); f != nil {
		tag, _ := f.Params.Get("tag")
		return tag
	}
	return ""
}

func ToTag(msg sip.Message) string {
	if t := msg.To(); t != nil {
		tag, _ := t.Params.Get("tag")
		return tag
	}
	return ""
}

// UserAgent returns req's User-Agent header value, or "" if absent.
func UserAgent(req *sip.Request) string {
	hs := req.GetHeaders("User-Agent")
	if len(hs) == 0 {
		return ""
	}
	return hs[0].Value()
}

// ContactURI returns a message's first Contact URI, if any.
func ContactURI(msg sip.Message) (sip.Uri, bool) {
	hs := msg.GetHeaders("Contact")
	if len(hs) == 0 {
		return sip.Uri{}, false
	}
	c, ok := hs[0].(*sip.ContactHeader)
	if !ok {
		return sip.Uri{}, false
	}
	return c.Address, true
}
