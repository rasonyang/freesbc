package shield

import "net/netip"

// Banned reports whether src is currently banned, without counting a
// request against it. It is what a transport read filter consults before
// a message is even parsed, so a banned source gets no response at all —
// not even the ones a SIP stack sends on its own before any handler runs
// (a stateless 400 for a malformed request, a 200 for a CANCEL).
func (s *Shield) Banned(src netip.Addr) bool { return s.bans.banned(src) }
