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
