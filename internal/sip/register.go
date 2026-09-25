package sip

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

// maxDeltaSeconds is the largest expires value RFC 3261 §20.19 keeps: a
// larger one is taken as 2**32-1. It also keeps the Duration well clear of
// overflow (2**32-1 s is about 136 years).
const maxDeltaSeconds = 1<<32 - 1

// DeltaSeconds parses an RFC 3261 delta-seconds value (1*DIGIT), as used
// by the expires Contact parameter and the Expires header. Anything that
// is not all digits — a sign, a space inside, an empty value — is not a
// value at all (ok false). A value above 2**32-1 is clamped to it, per
// §20.19, rather than wrapping around into a negative Duration.
func DeltaSeconds(v string) (d time.Duration, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n > maxDeltaSeconds {
		// All digits, so the only possible error is ErrRange.
		n = maxDeltaSeconds
	}
	return time.Duration(n) * time.Second, true
}

// GrantedExpires reads what the registrar actually granted, preferring a
// Contact's expires parameter over the response's Expires header, and
// falling back to requested when neither carries a valid value.
//
// A 2xx to REGISTER lists every current binding of the AoR (RFC 3261 §10.3
// step 8), including other devices'. ours, when given, picks out the
// Contact that is this registration's binding; only that Contact's
// expires is read, so another device's lifetime is never taken for ours.
// Without it the first Contact with a valid expires wins, which is right
// only when the registration is the AoR's single binding.
//
// Values are delta-seconds (DeltaSeconds): a negative or malformed one is
// ignored and an oversized one clamped, so the result is never negative.
func GrantedExpires(res *sip.Response, requested time.Duration, ours ...func(sip.Uri) bool) time.Duration {
	match := func(sip.Uri) bool { return true }
	if len(ours) > 0 && ours[0] != nil {
		match = ours[0]
	}
	for _, h := range res.GetHeaders("Contact") {
		c, ok := h.(*sip.ContactHeader)
		if !ok || c.Params == nil || !match(c.Address) {
			continue
		}
		if v, ok := c.Params.Get("expires"); ok {
			if d, ok := DeltaSeconds(v); ok {
				return d
			}
		}
	}
	if h := res.GetHeader("Expires"); h != nil {
		if d, ok := DeltaSeconds(h.Value()); ok {
			return d
		}
	}
	if requested < 0 {
		return 0
	}
	return requested
}

// ParseBindIP turns a configured bind address into a netip.Addr. An unset
// address is the zero Addr (every interface) with no error. An address
// that does not parse is an error, never every interface: the caller asked
// for one address, and binding all of them would expose a socket on
// interfaces it was meant to stay off. Only the bind plane — the
// advertised SDP address lives on the signaling side; the two stay
// independent so NAT/VPN deployments can bind privately and advertise
// publicly.
func ParseBindIP(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("sip: bind address %q: %w", s, err)
	}
	return ip, nil
}
