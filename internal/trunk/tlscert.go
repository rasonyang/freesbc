package trunk

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/freesbc/freesbc/internal/config"
)

// loadServerTLSConfig loads the CONFIGURED inbound TLS identity (T-17/F-13)
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

// buildClientTLSConfig builds the ONE outbound TLS config sipgo uses for
// every tls dial (sipgo v1.4.3 accepts a single UA-wide *tls.Config — see
// WithUserAgenTLSConfig — so per-peer settings are merged here, T-17/F-13):
//
//   - RootCAs = the system roots PLUS every peer's tls_ca bundle, so a
//     carrier with a private/self-signed CA is reachable with FULL
//     verification (previously such carriers were simply undialable).
//     Peers share the merged pool: a certificate chaining to any
//     configured CA verifies — acceptable for one operator's own trusted
//     carrier set, and still strict against anything outside it.
//   - Certificates = every peer's tls_client_cert/key pair. Go's client
//     selection sends the certificate whose issuer the server's
//     acceptable-CA list names, falling back to the first — with a single
//     configured pair (the common case) it is always the one sent.
//
// MinVersion is pinned to TLS 1.2. Returns nil when no peer configures any
// TLS material — sipgo's default (system roots only, Go default minimum)
// then applies exactly as before. File errors abort startup: a configured
// anchor that can't be loaded must not silently degrade to system-only
// verification.
func buildClientTLSConfig(peers map[string]*config.Peer) (*tls.Config, error) {
	var caFiles []string
	var certs []tls.Certificate
	for name, p := range peers {
		if p.TLSCA != "" {
			caFiles = append(caFiles, p.TLSCA)
		}
		if p.TLSClientCert != "" {
			cert, err := tls.LoadX509KeyPair(p.TLSClientCert, p.TLSClientKey)
			if err != nil {
				return nil, fmt.Errorf("peers.%s tls client cert/key: %w", name, err)
			}
			certs = append(certs, cert)
		}
	}
	if len(caFiles) == 0 && len(certs) == 0 {
		return nil, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	for _, f := range caFiles {
		caPEM, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("peer tls_ca %s: %w", f, err)
		}
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("peer tls_ca %s: no certificates found", f)
		}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: certs,
	}, nil
}
