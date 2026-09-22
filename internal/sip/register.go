package sip

import (
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

// ParseBindIP turns a configured bind address into a netip.Addr, or the
// zero Addr (every interface) when unset or unparseable. Only the bind
// plane — the advertised SDP address lives on the signaling side; the two
// stay independent so NAT/VPN deployments can bind privately and advertise
// publicly.
func ParseBindIP(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return ip
}
