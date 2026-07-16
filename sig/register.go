package sig

import (
	"context"
	"fmt"
	"log/slog"
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

const (
	// regBackoffMin is the initial retry delay after a failed register.
	regBackoffMin = 5 * time.Second
	// regBackoffMax is the ceiling the exponential backoff saturates at.
	regBackoffMax = 60 * time.Second
	// regRefreshFloor is the minimum delay before a refresh REGISTER, even
	// if 0.9x the granted lifetime would be shorter (guards against a
	// registrar granting a very short lifetime causing a refresh storm).
	regRefreshFloor = 10 * time.Second
)

// registration runs one peer's register→refresh→backoff loop. It is built
// by the manager (Task 5), one per configured outbound-register peer.
type registration struct {
	client        *sipgo.Client
	params        regParams
	setRegistered func(name string, ok bool)
	log           *slog.Logger
}

// run blocks until ctx is cancelled, keeping the peer registered: it
// registers, marks the peer registered, refreshes at ~0.9×granted (floor
// regRefreshFloor), and on any failure marks it unregistered and retries
// with exponential backoff (regBackoffMin doubling to regBackoffMax, reset
// to regBackoffMin on the next success). On ctx cancellation it best-effort
// un-REGISTERs before returning.
func (rg *registration) run(ctx context.Context, requested time.Duration) {
	backoff := regBackoffMin
	for {
		granted, err := registerOnce(ctx, rg.client, rg.params, requested)
		if ctx.Err() != nil {
			break
		}
		var wait time.Duration
		if err != nil {
			rg.setRegistered(rg.params.Name, false)
			rg.log.Warn("register failed", "peer", rg.params.Name, "err", err, "retry_in", backoff)
			wait = backoff
			if backoff *= 2; backoff > regBackoffMax {
				backoff = regBackoffMax
			}
		} else {
			rg.setRegistered(rg.params.Name, true)
			backoff = regBackoffMin
			wait = time.Duration(float64(granted) * 0.9)
			if wait < regRefreshFloor {
				wait = regRefreshFloor
			}
			rg.log.Info("registered", "peer", rg.params.Name, "granted", granted, "refresh_in", wait)
		}
		select {
		case <-ctx.Done():
			rg.unregister()
			return
		case <-time.After(wait):
		}
	}
	rg.unregister()
}

// unregister sends a best-effort Expires:0 REGISTER, bounded to a fixed
// timeout independent of the (already-cancelled) run loop's ctx, and marks
// the peer unregistered regardless of whether the registrar could be
// reached — the peer should not be treated as registered once we've
// stopped refreshing it.
func (rg *registration) unregister() {
	rg.setRegistered(rg.params.Name, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := registerOnce(ctx, rg.client, rg.params, 0); err != nil {
		rg.log.Debug("un-register failed", "peer", rg.params.Name, "err", err)
	}
}
