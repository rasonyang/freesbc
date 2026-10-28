package admin

import "github.com/freesbc/freesbc/internal/config"

// redactConfig returns a JSON-marshalable view of cfg with the one secret,
// admin.password_hash, replaced by "***". The view is the config's own
// shape with JSON-friendly keys: it builds a bespoke map rather than
// marshaling cfg (which carries yaml: tags, not json:, and holds the live
// secret) and never mutates cfg.
func redactConfig(cfg *config.Config) any {
	view := map[string]any{
		"public":  map[string]any{"ip": cfg.Public.IP, "bind": cfg.Public.Bind},
		"private": map[string]any{"ip": cfg.Private.IP},
		"rtp":     map[string]any{"min": cfg.RTP.Min, "max": cfg.RTP.Max},
		"edge": map[string]any{
			"switch":              cfg.Edge.Switch,
			"switch_carrier_port": cfg.Edge.SwitchCarrierPort,
			"listen": map[string]any{"udp": cfg.Edge.Listen.UDP, "tcp": cfg.Edge.Listen.TCP, "tls": cfg.Edge.Listen.TLS,
				"ws": cfg.Edge.Listen.WS, "wss": cfg.Edge.Listen.WSS},
			"advertise": map[string]any{"udp": cfg.Edge.Advertise.UDP, "tcp": cfg.Edge.Advertise.TCP, "tls": cfg.Edge.Advertise.TLS,
				"ws": cfg.Edge.Advertise.WS, "wss": cfg.Edge.Advertise.WSS},
			"carriers":            redactCarriers(cfg.Edge.Carriers),
			"carrier_sources":     cfg.Edge.CarrierSources,
			"srtp":                cfg.Edge.SRTP,
			"allow_insecure_sdes": cfg.Edge.AllowInsecureSDES,
		},
		"shield": map[string]any{
			"rate_limit":         cfg.Shield.RateLimit,
			"carrier_rate_limit": cfg.Shield.CarrierRateLimit,
			"ban":                cfg.Shield.Ban.Std().String(),
			"max_sessions":       cfg.Shield.MaxSessions,
			"invite_rate_limit":  cfg.Shield.InviteRateLimit,
			"register_ban":       cfg.Shield.RegisterBan,
			"register_ban_aor":   cfg.Shield.RegisterBanAOR,
			"admission_ban":      cfg.Shield.AdmissionBan,
		},
	}
	if cfg.TLS != nil {
		view["tls"] = map[string]any{"cert": cfg.TLS.Cert, "key": cfg.TLS.Key}
	}
	if h := cfg.HEP; h != nil {
		v := map[string]any{"address": h.Address, "transport": h.Transport, "capture_id": h.CaptureID,
			"node_name": h.NodeName, "redact_auth": cfg.HEPRedact()}
		if h.TLS != nil {
			// File paths, not key material.
			v["tls"] = map[string]any{"ca": h.TLS.CA, "cert": h.TLS.Cert, "key": h.TLS.Key}
		}
		view["hep"] = v
	}
	if cfg.Admin != nil {
		a := map[string]any{"listen": cfg.Admin.Listen, "allow_remote": cfg.Admin.AllowRemote,
			"allowed_hosts": cfg.Admin.AllowedHosts, "pprof": cfg.Admin.Pprof}
		if cfg.Admin.PasswordHash != "" {
			a["password_hash"] = "***"
		}
		view["admin"] = a
	}
	return view
}

// redactCarriers shows a plain "host[:port]" carrier as that string and any
// other as a mapping. Certificate and key entries are file paths, not key
// material, so nothing here is secret.
func redactCarriers(m map[string]config.CarrierConfig) map[string]any {
	out := make(map[string]any, len(m))
	for name, c := range m {
		if c.Plain() {
			out[name] = c.Host
			continue
		}
		v := map[string]any{"host": c.Host, "transport": c.Transport}
		if c.SRTP != "" {
			v["srtp"] = c.SRTP
		}
		for k, p := range map[string]string{"ca_file": c.CAFile, "client_cert": c.ClientCert, "client_key": c.ClientKey} {
			if p != "" {
				v[k] = p
			}
		}
		out[name] = v
	}
	return out
}
