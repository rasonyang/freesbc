package config

import (
	"strings"
	"testing"
)

// TestValidateTLSPeersNeedDistinctHosts: outbound TLS chooses a peer's
// trust roots by the dialled host alone, so two TLS peers that share a
// hostname or an IP (on any ports) are rejected. Non-TLS peers, and a TLS
// peer next to a non-TLS one on the same host, are unaffected.
//
// audit: P2-TRK-016
func TestValidateTLSPeersNeedDistinctHosts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		a, b     *Peer
		wantFail bool
	}{
		{"same hostname", &Peer{Address: "sip.example.net", Transport: "tls"}, &Peer{Address: "SIP.example.net.:5999", Transport: "tls"}, true},
		{"same ip:port", &Peer{Address: "192.0.2.1:5061", Transport: "tls"}, &Peer{Address: "192.0.2.1:5061", Transport: "tls"}, true},
		{"same ip other port", &Peer{Address: "192.0.2.1:5061", Transport: "tls"}, &Peer{Address: "192.0.2.1:5062", Transport: "tls"}, true},
		{"distinct hosts", &Peer{Address: "a.example.net", Transport: "tls"}, &Peer{Address: "b.example.net", Transport: "tls"}, false},
		{"tls next to udp", &Peer{Address: "192.0.2.1:5061", Transport: "tls"}, &Peer{Address: "192.0.2.1:5060", Transport: "udp"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			for n, p := range map[string]*Peer{"ta": tc.a, "tb": tc.b} {
				p.AllowedIPs = []string{"198.51.100.1"}
				c.Peers[n] = p
			}
			withDefaults(c)
			err := c.validate()
			failed := err != nil && strings.Contains(err.Error(), "TLS peers must have distinct hosts")
			if failed != tc.wantFail {
				t.Fatalf("validate() = %v, want shared-host rejection %v", err, tc.wantFail)
			}
			if failed && !strings.Contains(err.Error(), "peers.tb:") {
				t.Errorf("error should name the second peer: %v", err)
			}
		})
	}
}
