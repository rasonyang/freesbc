package shield

import "net/netip"

// Banned reports whether src is currently banned, without counting a
// request against it. It is what a transport read filter consults before
// a message is even parsed, so a banned source gets no response at all —
// not even the ones a SIP stack sends on its own before any handler runs
// (a stateless 400 for a malformed request, a 200 for a CANCEL).
//
// An IPv6 ban covers the source's whole /64 (bucketKey), so a carrier
// address inside a banned /64 is not banned: a hit on the table is
// discarded for a carrier source.
func (s *Shield) Banned(src netip.Addr) bool {
	src = src.Unmap()
	return s.bans.banned(bucketKey(src)) && !s.isCarrier(src)
}

// banKeyString renders a bucketKey for display: an IPv4 address as is, an
// IPv6 key as its /64 prefix.
func banKeyString(key netip.Addr) string {
	if key.Is6() {
		return netip.PrefixFrom(key, 64).String()
	}
	return key.String()
}
