package config

import (
	"fmt"
	"strings"
)

// NATForward is one port (or port range) the router in front of FreeSBC must
// forward to public.bind: from Ports on public.ip to the same number, or to
// To when edge.advertise translates the port.
type NATForward struct {
	Proto string // "udp" or "tcp"
	Ports string // "5060" or "20000-29999": the external (advertised) side
	To    int    // the listen port when it differs from Ports, else 0
	Label string // the edge.listen key, "rtp" for media
}

// String renders "udp/5060", "udp/16060->5060" for a translated port, plus
// " (label)" when the label adds information.
func (f NATForward) String() string {
	s := f.Proto + "/" + f.Ports
	if f.To != 0 {
		s += fmt.Sprintf("->%d", f.To)
	}
	if f.Label != "" && f.Label != f.Proto {
		s += " (" + f.Label + ")"
	}
	return s
}

// NATMode reports whether FreeSBC sits behind NAT: the advertised public.ip is
// not the address public sockets bind (1:1 NAT), or edge.advertise names a
// port other than a listener's own (port translation).
func (c *Config) NATMode() bool { return c.PublicBind() != c.PublicIP() || c.PortTranslated() }

// NATForwards lists every public port that must be reachable from clients:
// each configured edge.listen socket (by its advertised port, with the
// listen port as To when edge.advertise translates it), then the rtp range
// over UDP, which is never translated. It is nil outside NAT mode. The admin
// API and the private socket are not here: neither binds on public.bind.
func (c *Config) NATForwards() []NATForward {
	if !c.NATMode() {
		return nil
	}
	var out []NATForward
	for _, tr := range Transports {
		port := c.Edge.Listen.Port(tr)
		if port == 0 {
			continue
		}
		proto := "tcp"
		if tr == "udp" {
			proto = "udp"
		}
		adv := c.AdvertisedPort(tr)
		f := NATForward{Proto: proto, Ports: fmt.Sprint(adv), Label: tr}
		if adv != port {
			f.To = port
		}
		out = append(out, f)
	}
	out = append(out, NATForward{Proto: "udp", Ports: fmt.Sprintf("%d-%d", c.RTP.Min, c.RTP.Max), Label: "rtp"})
	return out
}

// NATChecklist is the text `check`, `run` and `init` show for a NAT setup:
// the advertised endpoints and the port forwards the router needs. It is
// empty outside NAT mode, and ends with a newline otherwise.
func (c *Config) NATChecklist() string {
	fw := c.NATForwards()
	if fw == nil {
		return ""
	}
	var adv, req []string
	for _, f := range fw {
		adv = append(adv, f.String())
		req = append(req, "  "+f.String())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "NAT mode: advertised public endpoint = %s (%s)\n", c.Public.IP, strings.Join(adv, " "))
	if c.PortTranslated() {
		fmt.Fprintf(&b, "REQUIRED forwards -> %s (external->internal where shown, else the same port number; the rtp range is never translated):\n%s\n",
			c.Public.Bind, strings.Join(req, "\n"))
	} else {
		fmt.Fprintf(&b, "REQUIRED forwards -> %s (same port numbers):\n%s\n", c.Public.Bind, strings.Join(req, "\n"))
	}
	b.WriteString("in-dialog requests (2xx ACK, BYE) use Contact/Record-Route, not Via:\n")
	b.WriteString("these ports MUST be reachable from clients.\n")
	return b.String()
}
