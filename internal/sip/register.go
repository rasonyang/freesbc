package sip

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

// GrantedExpires reads what the registrar actually granted, preferring the
// response's Contact expires parameter over its Expires header.
func GrantedExpires(res *sip.Response, requested time.Duration) time.Duration {
	for _, h := range res.GetHeaders("Contact") {
		c, ok := h.(*sip.ContactHeader)
		if !ok || c.Params == nil {
			continue
		}
		if v, ok := c.Params.Get("expires"); ok {
			if n, err := strconv.Atoi(v); err == nil {
				return time.Duration(n) * time.Second
			}
		}
	}
	if h := res.GetHeader("Expires"); h != nil {
		if n, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil {
			return time.Duration(n) * time.Second
		}
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
