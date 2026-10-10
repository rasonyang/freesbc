package app

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/freesbc/freesbc/internal/config"
)

// fakeInit returns options with injected detectors and no network.
func fakeInit(t *testing.T, priv, route, pub string) (InitOptions, *int) {
	t.Helper()
	lookups := new(int)
	addr := func(s string) (netip.Addr, error) {
		if s == "" {
			return netip.Addr{}, errors.New("none")
		}
		return netip.MustParseAddr(s), nil
	}
	return InitOptions{
		Path:            filepath.Join(t.TempDir(), "freesbc.yaml"),
		PrivateIPToward: func(netip.AddrPort) (netip.Addr, error) { return addr(priv) },
		DefaultRouteIP:  func() (netip.Addr, error) { return addr(route) },
		LookupPublicIP: func(context.Context) (netip.Addr, error) {
			*lookups++
			return addr(pub)
		},
	}, lookups
}

func parseFile(t *testing.T, path string) *config.Config {
	t.Helper()
	c, err := config.Load(path)
	if err != nil {
		data, _ := os.ReadFile(path)
		t.Fatalf("generated config invalid: %v\n%s", err, data)
	}
	return c
}

func TestInitTopologies(t *testing.T) {
	tests := []struct {
		name                string
		priv, route, pub    string
		wantIP, wantBind    string
		wantBindKeyInOutput bool
	}{
		{"single NIC behind NAT", "10.0.0.2", "172.31.5.10", "203.0.113.7", "203.0.113.7", "172.31.5.10", true},
		{"dual NIC", "10.77.0.2", "192.0.2.10", "192.0.2.10", "192.0.2.10", "192.0.2.10", false},
		{"direct public IP, lookup fails", "10.77.0.2", "192.0.2.10", "", "192.0.2.10", "192.0.2.10", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, lookups := fakeInit(t, tc.priv, tc.route, tc.pub)
			o.Switch = "10.77.0.10"
			if err := Init(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			c := parseFile(t, o.Path)
			if c.Public.IP != tc.wantIP || c.Public.Bind != tc.wantBind || c.Private.IP != tc.priv {
				t.Errorf("got ip=%s bind=%s priv=%s", c.Public.IP, c.Public.Bind, c.Private.IP)
			}
			if sw := c.Switches(); len(sw) != 1 || sw[0].String() != "10.77.0.10:5060" {
				t.Errorf("switch = %v, want 10.77.0.10:5060 (bare IP gets :5060)", sw)
			}
			data, _ := os.ReadFile(o.Path)
			if has := strings.Contains(string(data), "bind:"); has != tc.wantBindKeyInOutput {
				t.Errorf("bind key present = %v, want %v\n%s", has, tc.wantBindKeyInOutput, data)
			}
			if strings.Contains(string(data), "admin:") {
				t.Error("non-interactive output has an admin section")
			}
			if *lookups != 1 {
				t.Errorf("lookups = %d, want 1", *lookups)
			}
			if runtime.GOOS != "windows" {
				if fi, _ := os.Stat(o.Path); fi.Mode().Perm() != 0o600 {
					t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
				}
			}
		})
	}
}

func TestInitExplicitValuesSkipDetection(t *testing.T) {
	o, lookups := fakeInit(t, "10.9.9.9", "172.16.0.1", "198.51.100.1")
	o.Switch, o.PrivateIP, o.PublicIP, o.PublicBind, o.UDPPort = "10.0.0.5:5070", "10.0.0.2", "203.0.113.7", "192.0.2.10", 5080
	if err := Init(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	c := parseFile(t, o.Path)
	if c.Public.IP != "203.0.113.7" || c.Public.Bind != "192.0.2.10" || c.Private.IP != "10.0.0.2" || c.Edge.Listen.UDP != 5080 {
		t.Errorf("explicit values not used: %+v %+v", c.Public, c.Edge.Listen)
	}
	if *lookups != 0 {
		t.Errorf("public lookup ran although --public-ip was given")
	}
}

func TestInitNoPublicLookup(t *testing.T) {
	o, lookups := fakeInit(t, "10.0.0.2", "192.0.2.10", "203.0.113.7")
	o.Switch, o.NoPublicLookup = "10.0.0.5:5060", true
	var errOut strings.Builder
	o.Err = &errOut
	if err := Init(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if *lookups != 0 {
		t.Error("lookup ran with NoPublicLookup")
	}
	if c := parseFile(t, o.Path); c.Public.IP != "192.0.2.10" {
		t.Errorf("public.ip = %s, want public.bind", c.Public.IP)
	}
}

func TestInitLookupNoticeNamesService(t *testing.T) {
	o, _ := fakeInit(t, "10.0.0.2", "192.0.2.10", "203.0.113.7")
	o.Switch = "10.0.0.5"
	var errOut strings.Builder
	o.Err = &errOut
	if err := Init(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "api.ipify.org") || !strings.Contains(errOut.String(), "--no-public-lookup") {
		t.Errorf("notice = %q", errOut.String())
	}
}

func TestInitRefusesExistingFile(t *testing.T) {
	o, lookups := fakeInit(t, "10.0.0.2", "192.0.2.10", "203.0.113.7")
	o.Switch = "10.0.0.5"
	if err := os.WriteFile(o.Path, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Init(context.Background(), o)
	if !errors.Is(err, ErrInitFileExists) || !strings.Contains(err.Error(), o.Path) {
		t.Fatalf("err = %v, want refusal naming the path", err)
	}
	if got, _ := os.ReadFile(o.Path); string(got) != "keep me" {
		t.Errorf("file was modified: %q", got)
	}
	if *lookups != 0 {
		t.Error("network lookup ran before the existing-file refusal")
	}
}

type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Error("input read in non-interactive mode")
	return 0, io.EOF
}

func TestInitNonInteractiveNeedsSwitchAndNeverReads(t *testing.T) {
	o, _ := fakeInit(t, "10.0.0.2", "192.0.2.10", "203.0.113.7")
	o.In = failReader{t}
	o.ReadPassword = func() (string, error) { t.Error("password read"); return "", nil }
	err := Init(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "switch") {
		t.Fatalf("err = %v, want missing switch error", err)
	}
	if _, serr := os.Stat(o.Path); !errors.Is(serr, os.ErrNotExist) {
		t.Error("file written despite error")
	}
}

func TestInitPrivateEqualsBind(t *testing.T) {
	o, _ := fakeInit(t, "10.0.0.2", "10.0.0.2", "")
	o.Switch = "10.0.0.5"
	err := Init(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "second IP") {
		t.Fatalf("err = %v, want second-IP error", err)
	}
	if _, serr := os.Stat(o.Path); !errors.Is(serr, os.ErrNotExist) {
		t.Error("file written despite error")
	}

	// bind defaulting to public.ip counts as well.
	o, _ = fakeInit(t, "10.0.0.2", "", "")
	o.Switch, o.PublicIP = "10.0.0.5", "10.0.0.2"
	if err := Init(context.Background(), o); err == nil || !strings.Contains(err.Error(), "second IP") {
		t.Fatalf("err = %v, want second-IP error", err)
	}
}

func TestInitBadSwitch(t *testing.T) {
	o, _ := fakeInit(t, "10.0.0.2", "192.0.2.10", "")
	o.Switch = "pbx.example.net:5060"
	if err := Init(context.Background(), o); err == nil || !strings.Contains(err.Error(), "edge.switch") {
		t.Fatalf("err = %v", err)
	}
}

func TestInitInteractive(t *testing.T) {
	o, lookups := fakeInit(t, "10.0.0.2", "172.31.5.10", "203.0.113.7")
	// switch typed, Enter for private.ip, bind overridden, Enter to look up,
	// Enter for public.ip, port overridden.
	o.Interactive = true
	o.In = strings.NewReader("10.0.0.5:5062\n\n192.0.2.10\n\n\n5080\n")
	var out strings.Builder
	o.Out = &out
	pws := []string{"s3cret-pw", "s3cret-pw"}
	o.ReadPassword = func() (string, error) { p := pws[0]; pws = pws[1:]; return p, nil }
	if err := Init(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	c := parseFile(t, o.Path)
	if c.Private.IP != "10.0.0.2" || c.Public.Bind != "192.0.2.10" || c.Public.IP != "203.0.113.7" || c.Edge.Listen.UDP != 5080 {
		t.Errorf("got priv=%s bind=%s ip=%s udp=%d", c.Private.IP, c.Public.Bind, c.Public.IP, c.Edge.Listen.UDP)
	}
	if sw := c.Switches(); sw[0].String() != "10.0.0.5:5062" {
		t.Errorf("switch = %v", sw)
	}
	if c.Admin == nil || bcrypt.CompareHashAndPassword([]byte(c.Admin.PasswordHash), []byte("s3cret-pw")) != nil {
		t.Errorf("admin hash does not verify: %+v", c.Admin)
	}
	if *lookups != 1 {
		t.Errorf("lookups = %d, want 1", *lookups)
	}
	for _, want := range []string{"[10.0.0.2]", "[172.31.5.10]", "Look up public IP via api.ipify.org? [Y/n]", "[203.0.113.7]", "[5060]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("prompts lack %q:\n%s", want, out.String())
		}
	}
}

func TestInitInteractiveDeclineLookupAndSkipAdmin(t *testing.T) {
	o, lookups := fakeInit(t, "10.0.0.2", "192.0.2.10", "203.0.113.7")
	o.Interactive = true
	o.In = strings.NewReader("10.0.0.5\n\n\nn\n\n\n")
	o.ReadPassword = func() (string, error) { return "", nil }
	if err := Init(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if *lookups != 0 {
		t.Error("lookup ran after the user declined")
	}
	c := parseFile(t, o.Path)
	if c.Public.IP != "192.0.2.10" || c.Admin != nil {
		t.Errorf("ip=%s admin=%v", c.Public.IP, c.Admin)
	}
}

func TestInitAdminPasswordMismatch(t *testing.T) {
	o, _ := fakeInit(t, "10.0.0.2", "192.0.2.10", "")
	o.Interactive = true
	o.In = strings.NewReader("10.0.0.5\n\n\n\n\n")
	o.NoPublicLookup = true
	pws := []string{"one", "two"}
	o.ReadPassword = func() (string, error) { p := pws[0]; pws = pws[1:]; return p, nil }
	if err := Init(context.Background(), o); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(o.Path); !errors.Is(serr, os.ErrNotExist) {
		t.Error("file written despite error")
	}
}
