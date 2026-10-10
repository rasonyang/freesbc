package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// metadataURL is the EC2-compatible instance metadata root.
const metadataURL = "http://169.254.169.254"

// PrivateIPToward returns the local source address the kernel would use to
// reach sw. A UDP "connect" sends no packet.
func PrivateIPToward(sw netip.AddrPort) (netip.Addr, error) {
	return localSourceFor(sw.String())
}

// DefaultRouteIP returns the local source address toward the default route,
// found by a UDP "connect" to a public address (no packet is sent).
func DefaultRouteIP() (netip.Addr, error) {
	return localSourceFor("192.0.2.1:9")
}

func localSourceFor(remote string) (netip.Addr, error) {
	c, err := net.Dial("udp", remote)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("unexpected local address %v", c.LocalAddr())
	}
	a, ok := netip.AddrFromSlice(ua.IP)
	if !ok || a.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("no local address toward %s", remote)
	}
	return a.Unmap(), nil
}

// LookupPublicIP asks PublicIPService (3 s), then the EC2-compatible
// metadata service (1 s per request) for the host's public IPv4 address.
func LookupPublicIP(ctx context.Context) (netip.Addr, error) {
	a, err := httpIP(ctx, 3*time.Second, http.MethodGet, PublicIPService, nil)
	if err == nil {
		return a, nil
	}
	if m, merr := metadataPublicIP(ctx); merr == nil {
		return m, nil
	}
	return netip.Addr{}, err
}

// metadataPublicIP reads latest/meta-data/public-ipv4 with an IMDSv2 token,
// falling back to a plain GET.
func metadataPublicIP(ctx context.Context) (netip.Addr, error) {
	hdr := map[string]string{}
	if tok, err := httpBody(ctx, time.Second, http.MethodPut, metadataURL+"/latest/api/token",
		map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"}); err == nil && tok != "" {
		hdr["X-aws-ec2-metadata-token"] = tok
	}
	return httpIP(ctx, time.Second, http.MethodGet, metadataURL+"/latest/meta-data/public-ipv4", hdr)
}

func httpIP(ctx context.Context, timeout time.Duration, method, url string, hdr map[string]string) (netip.Addr, error) {
	body, err := httpBody(ctx, timeout, method, url, hdr)
	if err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(body)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s: reply is not an IP address", url)
	}
	return a.Unmap(), nil
}

func httpBody(ctx context.Context, timeout time.Duration, method, url string, hdr map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
