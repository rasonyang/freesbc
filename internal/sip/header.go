package sip

import "github.com/emiago/sipgo/sip"

// Editable is a SIP message whose headers can be removed. sipgo's Message
// interface exposes append and prepend but not removal, even though both
// *sip.Request and *sip.Response implement it — an element that edits
// headers needs removal on both, so the interface is named here rather
// than duplicating every helper for the two concrete types.
type Editable interface {
	sip.Message
	RemoveHeader(name string) bool
}

var (
	_ Editable = (*sip.Request)(nil)
	_ Editable = (*sip.Response)(nil)
)

// RemoveHeaders strips every header of a name.
//
// sipgo's RemoveHeader deletes only the FIRST match — the right semantics
// for popping the top Via or Route, and the wrong ones everywhere else. A
// message may legitimately carry several Contacts (a phone registering two
// devices in one REGISTER, a redirect), and leaving the extras in place
// while adding one of our own would hand the far side the endpoint's
// address alongside the SBC's, defeating the point of anchoring.
func RemoveHeaders(msg Editable, name string) {
	for msg.RemoveHeader(name) {
	}
}

// SetContact replaces every Contact header with one URI. Used on both the
// request and the response path: an element that anchors signaling must
// make sure the Contact each side sees is its own, never the far
// endpoint's.
func SetContact(msg Editable, u sip.Uri) {
	RemoveHeaders(msg, "Contact")
	msg.AppendHeader(&sip.ContactHeader{Address: u})
}

// SetSDPBody replaces a message's body with an SDP one, keeping
// Content-Type and Content-Length consistent.
func SetSDPBody(msg Editable, body []byte) {
	RemoveHeaders(msg, "Content-Type")
	msg.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	msg.SetBody(body)
}
