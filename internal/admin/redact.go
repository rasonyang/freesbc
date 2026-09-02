package admin

import "github.com/freesbc/freesbc/internal/config"

// redactConfig returns a JSON-marshalable view of cfg with secrets replaced
// by "***": admin.auth.password_hash and every peers.<name>.auth.password.
// It builds a bespoke map rather than marshaling cfg (which carries yaml:
// tags, not json:, and holds the live secret values) — it never mutates cfg.
func redactConfig(cfg *config.Config) any {
	peers := map[string]any{}
	for name, p := range cfg.Peers {
		pv := map[string]any{
			"address":   p.Address,
			"transport": p.Transport,
			"srtp":      p.SRTP,
			"register":  p.Register,
		}
		if p.Auth != nil {
			auth := map[string]any{"username": p.Auth.Username}
			if p.Auth.Password != "" {
				auth["password"] = "***"
			}
			pv["auth"] = auth
		}
		peers[name] = pv
	}
	view := map[string]any{"peers": peers}
	if cfg.Admin != nil {
		adminView := map[string]any{"listen": cfg.Admin.Listen}
		a := map[string]any{"username": cfg.Admin.Auth.Username}
		if cfg.Admin.Auth.PasswordHash != "" {
			a["password_hash"] = "***"
		}
		adminView["auth"] = a
		view["admin"] = adminView
	}
	// Routes carry no secrets, so the parsed values are exposed as-is.
	view["routes"] = cfg.Routes
	return view
}
