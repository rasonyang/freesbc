package sig

import "github.com/freesbc/freesbc/config"

// matchRoute returns the first route whose From equals fromPeer and whose
// match.to regex matches toNumber. A route with no match clause (nil
// compiled regex) matches any number. Routes are tried in config order;
// the first hit wins (spec §5: no priority numbers). ok is false when no
// route matches — the caller rejects such calls (404 in M3.3).
func matchRoute(cfg *config.Config, fromPeer, toNumber string) (*config.Route, bool) {
	for _, r := range cfg.Routes {
		if r.From != fromPeer {
			continue
		}
		if re := r.CompiledMatch(); re != nil && !re.MatchString(toNumber) {
			continue
		}
		return r, true
	}
	return nil, false
}

// transformNumber applies a route's number transform. When the route has a
// transform, route.Transform.To is a regexp replacement template expanded
// against route.CompiledMatch() (which is guaranteed non-nil whenever a
// transform is set — config validation enforces "transform requires
// match"). Capture groups are referenced as $1 or, next to literal digits,
// ${1}. With no transform, the number passes through unchanged.
func transformNumber(route *config.Route, toNumber string) string {
	if route.Transform == nil || route.Transform.To == "" {
		return toNumber
	}
	re := route.CompiledMatch()
	return re.ReplaceAllString(toNumber, route.Transform.To)
}
