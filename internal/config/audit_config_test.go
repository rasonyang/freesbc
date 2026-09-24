package config

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// Audit tests (docs/audit/REPORT.md). A failing test here is the
// deliverable: it demonstrates a defect. Do not make it pass by editing the
// test; fix the production code instead.

// auditTrunkYAML is minimalYAML with a caller-supplied listen block.
func auditTrunkYAML(listen string) string {
	return listen + `
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: pbx
    to: [pbx]
`
}

// auditParseNoPanic runs Parse and converts a panic into an error string.
func auditParseNoPanic(src string) (cfg *Config, err error, panicked any) {
	defer func() {
		if r := recover(); r != nil {
			panicked = r
		}
	}()
	cfg, err = Parse([]byte(src))
	return cfg, err, nil
}

// audit: P2-CFG-001
// docs/design.md:316-318 and reload.go:16-18: a bad config is rejected with
// an error, never a crash. Null map/list entries must be errors.
func TestAuditParseNullEntriesDoNotPanic(t *testing.T) {
	cases := map[string]string{
		"null peer":         strings.Replace(minimalYAML, "peers:\n", "peers:\n  a:\n", 1),
		"null route":        minimalYAML + "  - ~\n",
		"null pstn gateway": withPSTN(proxyYAML, "  pstn:\n    match: 203.0.113.7:16060\n    gateways:\n      gw1:\n    routes:\n      - to: [gw1]\n"),
		"null pstn route":   withPSTN(proxyYAML, "  pstn:\n    match: 203.0.113.7:16060\n    gateways:\n      gw1:\n        address: 223.76.90.4:16060\n    routes:\n      - ~\n"),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			_, err, p := auditParseNoPanic(src)
			if p != nil {
				t.Fatalf("Parse panicked instead of returning an error: %v", p)
			}
			if err == nil {
				t.Fatalf("Parse accepted a null entry")
			}
		})
	}
}

// audit: P2-CFG-001
// The reload path runs Parse in the Watch goroutine, which has no recover.
// A hand-edited null entry must leave the process alive with the previous
// snapshot. The Watch runs in a child process so the crash does not take the
// whole test binary down.
func TestAuditWatchSurvivesNullEntryReload(t *testing.T) {
	if os.Getenv("AUDIT_WATCH_HELPER") == "1" {
		auditWatchHelper()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuditWatchSurvivesNullEntryReload$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AUDIT_WATCH_HELPER=1", "AUDIT_WATCH_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "AUDIT-ALIVE") {
		first := string(out)
		if i := strings.Index(first, "goroutine "); i > 0 {
			first = first[:i]
		}
		t.Fatalf("process died on a null-entry reload (err=%v):\n%s", err, first)
	}
}

func auditWatchHelper() {
	dir := os.Getenv("AUDIT_WATCH_DIR")
	path := filepath.Join(dir, "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o600); err != nil {
		panic(err)
	}
	cfg, err := Load(path)
	if err != nil {
		panic(err)
	}
	store := NewStore(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Watch(ctx, path, store, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	time.Sleep(300 * time.Millisecond) // let the watcher register
	bad := strings.Replace(minimalYAML, "peers:\n", "peers:\n  a:\n", 1)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(bad), 0o600); err != nil {
		panic(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		panic(err)
	}
	time.Sleep(1500 * time.Millisecond) // > reloadDebounce
	if store.Current() != cfg {
		fmt.Println("snapshot replaced by a bad config")
		os.Exit(3)
	}
	fmt.Println("AUDIT-ALIVE")
}

// audit: P2-CFG-003 (also P2-ADM-001)
// loader.go:23-27 / CLAUDE.md: errors never echo a secret. Validation runs
// after ${VAR} expansion and prints field values with %q.
func TestAuditValidationErrorDoesNotEchoEnv(t *testing.T) {
	const sentinel = "audit-sentinel-s3cr3t"
	t.Setenv("AUDIT_SECRET", sentinel)
	src := auditTrunkYAML("listen:\n  sip: [udp://0.0.0.0:5060]\n  media:\n    public_ip: \"${AUDIT_SECRET}\"\n")
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("expected a validation error")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("validation error echoes the expanded env value:\n%v", err)
	}
}

// audit: P2-CFG-004
// `check` (Parse) must reject what `run` rejects.
func TestAuditCheckRejectsWhatRunRejects(t *testing.T) {
	cases := map[string]string{
		"upstream hostname": strings.Replace(proxyYAML, "address: 10.77.0.10:5060", "address: fs.example.com:5060", 1),
		"pstn.match hostname": withPSTN(proxyYAML,
			"  pstn:\n    address: 223.76.90.4:16060\n    match: fs.example.invalid:16060\n"),
		"duplicate listen.sip":              auditTrunkYAML("listen:\n  sip: [udp://127.0.0.1:5070, udp://127.0.0.1:5070]\n"),
		"trunk and edge share a UDP socket": proxyYAML + auditTrunkYAML("listen:\n  sip: [udp://0.0.0.0:16060]\n  media:\n    port_range: 50000-50099\n"),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err, p := auditParseNoPanic(src); p != nil {
				t.Fatalf("Parse panicked: %v", p)
			} else if err == nil {
				t.Errorf("Parse accepted a config that `run` rejects")
			}
		})
	}
}

// audit: P2-CFG-005
// A named capture group reference in a route transform is a regexp template,
// not an environment variable.
func TestAuditNamedGroupNotExpandedAsEnv(t *testing.T) {
	src := strings.Replace(minimalYAML, "    to: [pbx]\n",
		"    match: { to: \"^(?P<num>[0-9]+)$\" }\n    transform: { to: \"+${num}\" }\n    to: [pbx]\n", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Errorf("named group ${num} treated as an env var: %v", err)
	}
	t.Setenv("num", "EVIL")
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tr := c.Routes[0].Transform; tr == nil || tr.To != "+${num}" {
		t.Errorf("transform template changed by env expansion: %+v", tr)
	}
}

// audit: P2-CFG-008
// An allowed_ips entry that validates must be able to match a source. Sources
// are Unmap()ed, so a 4in6 prefix can never match.
func TestAudit4in6AllowedIPsMatchOrReject(t *testing.T) {
	for _, entry := range []string{"::ffff:10.0.0.1", "::ffff:0:0/96"} {
		t.Run(entry, func(t *testing.T) {
			src := strings.Replace(minimalYAML, "allowed_ips: [10.0.0.0/8]", "allowed_ips: [\""+entry+"\"]", 1)
			c, err := Parse([]byte(src))
			if err != nil {
				return // rejected: acceptable
			}
			if !c.Peers["pbx"].AllowsIP(netip.MustParseAddr("10.0.0.1")) {
				t.Errorf("allowed_ips %q validates but never matches 10.0.0.1", entry)
			}
		})
	}
}

// audit: P2-CFG-009
// A trunk call binds two RTP/RTCP pairs (4 ports); a range that cannot hold
// one call must not validate.
func TestAuditTrunkPortRangeHoldsOneCall(t *testing.T) {
	src := auditTrunkYAML("listen:\n  sip: [udp://0.0.0.0:5060]\n  media:\n    port_range: 30000-30001\n")
	if _, err := Parse([]byte(src)); err == nil {
		t.Errorf("a 2-port trunk range validates but cannot hold one call")
	}
}

// auditKnownPanicSites are crash signatures already reported. With
// AUDIT_FUZZ_SKIP_KNOWN=1 the fuzzer ignores them so it can look for new
// ones; without it every panic fails the target.
var auditKnownPanicSites = []string{
	"goccy/go-yaml",            // P3-CORE-001
	"config.withDefaults",      // P2-CFG-001
	"config.proxyWithDefaults", // P2-CFG-001
	"(*Config).validate",       // P2-CFG-001
	"(*Config).validateProxy",  // P2-CFG-001
}

// audit: fuzz (crash hunt; P2-CFG-001, P3-CORE-001)
// Parse on arbitrary YAML must return an error, never panic.
func FuzzAuditConfigParse(f *testing.F) {
	skipKnown := os.Getenv("AUDIT_FUZZ_SKIP_KNOWN") == "1"
	f.Add([]byte(minimalYAML))
	f.Add([]byte(proxyYAML))
	f.Add([]byte(withPSTN(proxyYAML, multiPSTN)))
	f.Add([]byte("listen:\n  sip: [udp://0.0.0.0:5060]\npeers: {}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if skipKnown {
			defer func() {
				if r := recover(); r != nil {
					stack := string(debug.Stack())
					for _, site := range auditKnownPanicSites {
						if strings.Contains(stack, site) {
							return
						}
					}
					panic(r)
				}
			}()
		}
		_, _ = Parse(data)
	})
}
