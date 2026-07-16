package sig

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// regParams is the immutable identity of one peer's registration: what
// registrar to talk to, which credentials to present, and what Contact to
// advertise. Task 4/5's lifecycle/manager build the periodic-refresh and
// shutdown un-register logic on top of this.
type regParams struct {
	Name          string
	RegistrarHost string
	RegistrarPort int
	Transport     string
	Username      string
	Password      string
	ContactIP     netip.Addr
	ContactPort   int
}

// registerOnce performs a single REGISTER exchange for p, requesting the
// given expires (0 = un-REGISTER). It handles a 401/407 digest challenge
// and returns the lifetime the registrar granted, or an error.
func registerOnce(ctx context.Context, client *sipgo.Client, p regParams, expires time.Duration) (time.Duration, error) {
	registrar := sip.Uri{Scheme: "sip", Host: p.RegistrarHost, Port: p.RegistrarPort}
	req := sip.NewRequest(sip.REGISTER, registrar)

	// The address-of-record: no userinfo is added to the Request-URI itself
	// (ClientRequestRegisterBuild strips it per RFC 3261 §10.2 anyway), but
	// From/To carry the registering identity.
	aor := sip.Uri{Scheme: "sip", User: p.Username, Host: p.RegistrarHost}
	req.AppendHeader(&sip.FromHeader{Address: aor, Params: newTagParams()})
	req.AppendHeader(&sip.ToHeader{Address: aor, Params: sip.NewParams()})

	contact := sip.Uri{Scheme: "sip", Host: p.ContactIP.String(), Port: p.ContactPort}
	if p.Transport != "" && p.Transport != "udp" {
		params := sip.NewParams()
		params.Add("transport", p.Transport)
		contact.UriParams = params
	}
	req.AppendHeader(&sip.ContactHeader{Address: contact})

	exp := sip.ExpiresHeader(uint32(expires.Seconds()))
	req.AppendHeader(&exp)

	// ClientRequestRegisterBuild fills in Via/CSeq/Call-ID/Max-Forwards (it
	// only sets a header when one isn't already present) and clears the
	// Request-URI's userinfo — must run after From/To/Contact/Expires are
	// set above, since it treats an existing CSeq as "retransmit, bump it"
	// rather than "not yet built".
	if err := sipgo.ClientRequestRegisterBuild(client, req); err != nil {
		return 0, fmt.Errorf("build register: %w", err)
	}

	res, err := client.Do(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("register: %w", err)
	}
	if res.StatusCode == sip.StatusUnauthorized || res.StatusCode == sip.StatusProxyAuthRequired {
		res, err = client.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: p.Username, Password: p.Password})
		if err != nil {
			return 0, fmt.Errorf("register digest: %w", err)
		}
	}
	if res.StatusCode != sip.StatusOK {
		return 0, fmt.Errorf("register rejected: %d %s", res.StatusCode, res.Reason)
	}
	return grantedExpires(res, expires), nil
}

// grantedExpires reads the lifetime the registrar granted: the Expires
// header if present, else the Contact's expires param, else whatever was
// requested (a registrar that omits both but still answers 200 is assumed
// to have granted what was asked).
func grantedExpires(res *sip.Response, requested time.Duration) time.Duration {
	if h := res.GetHeader("Expires"); h != nil {
		if n, err := strconv.Atoi(h.Value()); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	if c := res.Contact(); c != nil {
		if v, ok := c.Params.Get("expires"); ok {
			if n, err := strconv.Atoi(v); err == nil {
				return time.Duration(n) * time.Second
			}
		}
	}
	return requested
}

// newTagParams returns header params carrying a fresh From tag (reuses
// freshTag, the M4.1 helper in sig/b2bua.go).
func newTagParams() sip.HeaderParams {
	pr := sip.NewParams()
	pr.Add("tag", freshTag())
	return pr
}
