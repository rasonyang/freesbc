package trunk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/freesbc/freesbc/internal/config"
)

// loadServerTLSConfig loads the CONFIGURED inbound TLS identity
// for tls:// SIP listeners: cert+key from disk, TLS >= 1.2, and — when
// clientCAPath is set — mutual TLS (clients must present a certificate
// chaining to that CA). File errors surface at listener bind time, failing
// startup rather than silently serving something else.
func loadServerTLSConfig(certPath, keyPath, clientCAPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("listen tls cert/key: %w", err)
	}
	conf := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if clientCAPath != "" {
		caPEM, err := os.ReadFile(clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("listen tls client ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("listen tls client ca: no certificates found in %s", clientCAPath)
		}
		conf.ClientCAs = pool
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return conf, nil
}

// tlsPeerKey is the context key under which the trunk carries the name of
// the peer a request is being sent to, down through sipgo's dial into the
// TLS handshake (sipgo v1.4.3 passes the request ctx to HandshakeContext,
// sip/transport_tls.go:73), where GetClientCertificate reads it back from
// cri.Context().
type tlsPeerKey struct{}

// withTLSPeer returns ctx carrying peer as the TLS client-certificate
// owner for any connection dialled under it.
func withTLSPeer(ctx context.Context, peer string) context.Context {
	return context.WithValue(ctx, tlsPeerKey{}, peer)
}

// peerTLSMaterial is one peer's outbound TLS material, loaded from disk at
// startup: the roots its server certificate must chain to (its tls_ca
// alone, or the system roots when it has none) and our client certificate
// for it (nil when it configures none).
type peerTLSMaterial struct {
	roots *x509.CertPool
	cert  *tls.Certificate
}

// clientTLS selects outbound TLS trust and identity PER PEER through
// callbacks on the one UA-wide client tls.Config sipgo v1.4.3 accepts
// (P2-TRK-016, option (c)):
//
//   - verify (VerifyConnection, with InsecureSkipVerify so Go's own
//     single-pool check is off) finds the ONE peer the connection belongs
//     to and verifies the chain against that peer's roots and the dialled
//     name against the leaf's SANs. The peer is matched by cs.ServerName
//     (the peer's address host, or an SRV target the resolver produced for
//     it). A peer dialled by IP literal sends no SNI, so cs.ServerName is
//     empty; the peer is then the unique IP-literal TLS peer whose IP is in
//     the leaf's IP SANs. No match, or more than one, fails the handshake.
//   - clientCert (GetClientCertificate) returns only the certificate of the
//     peer named in the handshake ctx (withTLSPeer), and no certificate
//     when the ctx names none.
//
// The peer set follows hot reload (peers() reads the current snapshot), but
// the material is loaded once at startup, so tls_ca/tls_client_cert changes
// remain restart-only. A TLS peer added by reload that names material which
// was never loaded fails closed rather than silently using the system roots.
type clientTLS struct {
	peers      func() map[string]*config.Peer
	srvTargets func(host, transport string) []string
	system     *x509.CertPool
	material   map[string]*peerTLSMaterial
}

// newClientTLS loads every TLS peer's material. File errors abort startup:
// a configured anchor that can't be loaded must not silently degrade to
// system-only verification. peers returns the current peer set; srvTargets
// returns the hosts the resolver last produced for an SRV name (nil when
// none), so a peer reached through SRV matches its targets' ServerName.
func newClientTLS(startup map[string]*config.Peer, peers func() map[string]*config.Peer, srvTargets func(host, transport string) []string) (*clientTLS, error) {
	system, err := x509.SystemCertPool()
	if err != nil || system == nil {
		system = x509.NewCertPool()
	}
	c := &clientTLS{peers: peers, srvTargets: srvTargets, system: system, material: map[string]*peerTLSMaterial{}}
	for name, p := range startup {
		m, err := loadPeerTLS(name, p, system)
		if err != nil {
			return nil, err
		}
		c.material[name] = m
	}
	return c, nil
}

func loadPeerTLS(name string, p *config.Peer, system *x509.CertPool) (*peerTLSMaterial, error) {
	m := &peerTLSMaterial{roots: system}
	if p.TLSCA != "" {
		caPEM, err := os.ReadFile(p.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("peers.%s tls_ca %s: %w", name, p.TLSCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("peers.%s tls_ca %s: no certificates found", name, p.TLSCA)
		}
		m.roots = pool
	}
	if p.TLSClientCert != "" {
		cert, err := tls.LoadX509KeyPair(p.TLSClientCert, p.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("peers.%s tls client cert/key: %w", name, err)
		}
		m.cert = &cert
	}
	return m, nil
}

// config returns the UA-wide client tls.Config. ServerName stays empty so
// sipgo sets it per dial to the dialled host.
func (c *clientTLS) config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Go's built-in verification is replaced, not skipped:
		// VerifyConnection runs on every handshake and does the chain and
		// name checks against the matched peer's roots.
		InsecureSkipVerify:   true,
		VerifyConnection:     c.verify,
		GetClientCertificate: c.clientCert,
	}
}

// materialFor returns the startup-loaded material of peer name, or the
// system roots for a peer added by reload that names no material.
func (c *clientTLS) materialFor(name string, p *config.Peer) (*peerTLSMaterial, error) {
	if m, ok := c.material[name]; ok {
		return m, nil
	}
	if p.TLSCA != "" || p.TLSClientCert != "" {
		return nil, fmt.Errorf("peer %s: tls_ca/tls_client_cert added by reload take effect on restart", name)
	}
	return &peerTLSMaterial{roots: c.system}, nil
}

// normHost lowercases a host name and strips a trailing root dot.
func normHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// matchPeer returns the one TLS peer the handshake belongs to and the name
// its certificate must be valid for.
func (c *clientTLS) matchPeer(cs tls.ConnectionState) (string, *config.Peer, string, error) {
	leaf := cs.PeerCertificates[0]
	sni := normHost(cs.ServerName)
	var names []string
	verifyName := sni
	peers := c.peers()
	for name, p := range peers {
		if p.Transport != "tls" {
			continue
		}
		host, _, explicitPort, isIP := classifyAddress(p.Address)
		switch {
		case sni != "":
			if isIP {
				continue
			}
			if normHost(host) == sni {
				names = append(names, name)
				continue
			}
			if !explicitPort && c.srvTargets != nil {
				for _, t := range c.srvTargets(host, p.Transport) {
					if normHost(t) == sni {
						names = append(names, name)
						break
					}
				}
			}
		default:
			// No SNI: the dial was to an IP literal (Go omits IPs from
			// SNI). Only an IP-literal peer whose IP the leaf names can be
			// the one dialled.
			if !isIP {
				continue
			}
			ip, _ := netip.ParseAddr(host)
			for _, san := range leaf.IPAddresses {
				if a, ok := netip.AddrFromSlice(san); ok && a.Unmap() == ip.Unmap() {
					names = append(names, name)
					verifyName = ip.String()
					break
				}
			}
		}
	}
	switch len(names) {
	case 0:
		return "", nil, "", fmt.Errorf("no TLS peer matches server %q", cs.ServerName)
	case 1:
		return names[0], peers[names[0]], verifyName, nil
	default:
		sort.Strings(names)
		return "", nil, "", fmt.Errorf("server %q matches several TLS peers %v", cs.ServerName, names)
	}
}

// verify is the VerifyConnection callback: the chain must reach the
// matched peer's roots and the leaf must be valid for the dialled name.
func (c *clientTLS) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("peer tls: no server certificate")
	}
	name, p, verifyName, err := c.matchPeer(cs)
	if err != nil {
		return fmt.Errorf("peer tls: %w", err)
	}
	m, err := c.materialFor(name, p)
	if err != nil {
		return fmt.Errorf("peer tls: %w", err)
	}
	inter := x509.NewCertPool()
	for _, ic := range cs.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         m.roots,
		Intermediates: inter,
		DNSName:       verifyName,
	}); err != nil {
		return fmt.Errorf("peer tls: peer %s: %w", name, err)
	}
	return nil
}

// clientCert is the GetClientCertificate callback: the certificate of the
// peer named in the handshake ctx, or none (an empty Certificate) when the
// ctx names no peer or the peer has no client certificate.
func (c *clientTLS) clientCert(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	name, _ := cri.Context().Value(tlsPeerKey{}).(string)
	if name == "" {
		return &tls.Certificate{}, nil
	}
	p, ok := c.peers()[name]
	if !ok {
		return &tls.Certificate{}, nil
	}
	m, err := c.materialFor(name, p)
	if err != nil {
		return nil, err
	}
	if m.cert == nil {
		return &tls.Certificate{}, nil
	}
	return m.cert, nil
}
