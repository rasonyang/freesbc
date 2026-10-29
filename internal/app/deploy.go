package app

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/edge"
)

// certWarnWindow is how close to expiry a leaf draws a warning.
const certWarnWindow = 30 * 24 * time.Hour

// CheckDeploy is Check plus what `run` would open: the tls pair, every tls
// carrier's ca_file and client pair, the HEP TLS files and, with
// localAddresses, the bind addresses. It binds no configured port, resolves
// no name and contacts no peer (an unaliased 127/8 address is probed with a
// bind on an ephemeral port, as run does). Every failure is collected, not
// just the first. report is the "config OK" line and the findings, one block
// per file. err (nil when all checks passed) joins the failures and is
// returned even when report is not empty. A config that does not load
// returns that error with an empty report. Private keys are never printed.
func CheckDeploy(path string, localAddresses bool) (report, note string, err error) {
	cfg, err := config.Load(path)
	if err != nil {
		return "", "", err
	}
	return checkDeploy(path, cfg, localAddresses, time.Now())
}

func checkDeploy(path string, cfg *config.Config, localAddresses bool, now time.Time) (report, note string, err error) {
	var out strings.Builder
	fmt.Fprintf(&out, "%s: config OK\n", path)
	var errs []error
	fail := func(key, files string, cause error) {
		errs = append(errs, fmt.Errorf("%s %s: %w", key, files, cause))
	}
	leaf := func(key, files string, cert tls.Certificate) {
		out.WriteString(describeLeaf(key, cert.Leaf, now))
		if cert.Leaf != nil && now.After(cert.Leaf.NotAfter) {
			errs = append(errs, fmt.Errorf("%s %s: certificate expired %s", key, files, cert.Leaf.NotAfter.UTC().Format(time.RFC3339)))
		}
	}
	pair := func(key, certFile, keyFile string) {
		cert, err := edge.LoadTLSPair(certFile, keyFile)
		if err != nil {
			fail(key, certFile+" "+keyFile, err)
			return
		}
		leaf(key, certFile, cert)
	}

	if t := cfg.TLS; t != nil {
		pair("tls.cert/tls.key", t.Cert, t.Key)
	}
	for _, c := range cfg.CarrierList() {
		if c.Transport != config.CarrierTLS {
			continue
		}
		key := "edge.carriers." + c.Name
		if c.CAFile == "" {
			fmt.Fprintf(&out, "%s.ca_file: unset, system roots\n", key)
		} else if _, err := edge.LoadCAPool(c.CAFile); err != nil {
			fail(key+".ca_file", c.CAFile, err)
		} else {
			fmt.Fprintf(&out, "%s.ca_file %s: loaded\n", key, c.CAFile)
		}
		if c.ClientCert != "" {
			pair(key+".client_cert/client_key", c.ClientCert, c.ClientKey)
		}
	}
	if h := cfg.HEP; h != nil && h.Transport == config.HEPTLS {
		var ca, cert, key string
		if h.TLS != nil {
			ca, cert, key = h.TLS.CA, h.TLS.Cert, h.TLS.Key
		}
		if conf, err := hepTLSConfig(h); err != nil {
			fail("hep.tls", fmt.Sprintf("ca %q cert %q key %q", ca, cert, key), err)
		} else {
			if ca == "" {
				out.WriteString("hep.tls.ca: unset, system roots\n")
			} else {
				fmt.Fprintf(&out, "hep.tls.ca %s: loaded\n", ca)
			}
			for _, c := range conf.Certificates {
				leaf("hep.tls.cert/hep.tls.key", cert, c)
			}
		}
	}
	if localAddresses {
		for _, a := range []struct {
			key string
			ip  netip.Addr
		}{{"public.bind", cfg.PublicBind()}, {"private.ip", cfg.PrivateIP()}} {
			if iface, err := edge.CheckLocalAddr(a.key, a.ip); err != nil {
				errs = append(errs, err)
			} else {
				fmt.Fprintf(&out, "%s %s: on interface %s\n", a.key, a.ip, iface)
			}
		}
	}
	return out.String(), cfg.NATChecklist(), errors.Join(errs...)
}

// describeLeaf is the report block for one certificate: subject, SANs,
// issuer and not-after, with a warning inside certWarnWindow of expiry.
func describeLeaf(key string, c *x509.Certificate, now time.Time) string {
	if c == nil {
		return key + ": loaded\n"
	}
	var sans []string
	for _, d := range c.DNSNames {
		sans = append(sans, "DNS:"+d)
	}
	for _, ip := range c.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	if len(sans) == 0 {
		sans = []string{"none"}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: loaded\n  subject:   %s\n  sans:      %s\n  issuer:    %s\n  not after: %s",
		key, c.Subject, strings.Join(sans, ", "), c.Issuer, c.NotAfter.UTC().Format(time.RFC3339))
	switch left := c.NotAfter.Sub(now); {
	case left < 0:
		b.WriteString(" (expired)")
	case left < certWarnWindow:
		fmt.Fprintf(&b, "\n  warning:   expires in %d days", int(left.Hours()/24))
	}
	b.WriteByte('\n')
	return b.String()
}
