package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// minimalYAML is the smallest valid v2 config.
const minimalYAML = `
public:
  ip: 203.0.113.7
private:
  ip: 10.77.0.2
edge:
  switch: [10.77.0.10:5060]
  listen: { udp: 5060 }
`

// with returns minimalYAML with extra top-level YAML appended.
func with(extra string) string { return minimalYAML + extra }

// replace returns src with old replaced by new, failing when old is absent.
func replace(t *testing.T, src, old, new string) string {
	t.Helper()
	if !strings.Contains(src, old) {
		t.Fatalf("%q not in test YAML", old)
	}
	return strings.Replace(src, old, new, 1)
}

func mustParse(t *testing.T, src string) *Config {
	t.Helper()
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c
}

func parseErr(t *testing.T, src string) string {
	t.Helper()
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatalf("Parse accepted:\n%s", src)
	}
	return err.Error()
}

func TestParseMinimalDefaults(t *testing.T) {
	c := mustParse(t, minimalYAML)
	if c.PublicIP() != netip.MustParseAddr("203.0.113.7") || c.PublicBind() != c.PublicIP() {
		t.Errorf("public ip/bind = %v/%v", c.PublicIP(), c.PublicBind())
	}
	if c.PrivateAddr() != netip.MustParseAddrPort("10.77.0.2:5060") {
		t.Errorf("private addr = %v", c.PrivateAddr())
	}
	if c.RTP != (PortRange{Min: 20000, Max: 29999}) {
		t.Errorf("rtp default = %+v", c.RTP)
	}
	if c.Shield.RateLimit != "20/s per_ip" || c.Shield.CarrierRateLimit != "200/s per_ip" || c.Shield.Ban.Std() != time.Hour {
		t.Errorf("shield defaults = %+v", c.Shield)
	}
	if got := c.Switches(); len(got) != 1 || got[0] != netip.MustParseAddrPort("10.77.0.10:5060") {
		t.Errorf("switches = %v", got)
	}
	if c.WebRTC() || c.Admin != nil || c.TLS != nil {
		t.Error("webrtc/admin/tls must default to off")
	}
}

func TestParseFullExample(t *testing.T) {
	src := `
public: { ip: 203.0.113.7, bind: 172.31.5.10 }
private: { ip: 10.77.0.2 }
rtp: 30000-30999
tls: { cert: /c.pem, key: /k.pem }
edge:
  switch: [10.77.0.10:5060, "[fd00::10]:5060"]
  switch_carrier_port: 5080
  listen: { udp: 5060, ws: 8080, wss: 443 }
  carriers:
    carrier-a: sip.carrier-a.com
    mobile: 223.76.90.4:16060
    v6: "[2001:db8::1]:5070"
  carrier_sources: [198.51.100.20, 203.0.113.0/28]
shield: { rate_limit: 5/m per_ip, carrier_rate_limit: 9/s per_ip, ban: 30m }
`
	c := mustParse(t, src)
	if c.PublicBind() != netip.MustParseAddr("172.31.5.10") || c.RTP.Min != 30000 {
		t.Errorf("bind/rtp: %v %+v", c.PublicBind(), c.RTP)
	}
	if !c.WebRTC() || c.Edge.SwitchCarrierPort != 5080 || len(c.Switches()) != 2 {
		t.Errorf("edge = %+v", c.Edge)
	}
	cl := c.CarrierList()
	if len(cl) != 3 || cl[0].Name != "carrier-a" || cl[0].Port != 5060 || cl[0].Literal() ||
		cl[1].Name != "mobile" || cl[1].Port != 16060 || !cl[1].Literal() ||
		cl[2].Name != "v6" || cl[2].Addr != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("carriers = %+v", cl)
	}
	// carrier_sources (2) plus the two literal-IP carriers.
	if n := len(c.CarrierNets()); n != 4 {
		t.Errorf("CarrierNets = %v", c.CarrierNets())
	}
	if c.Shield.Ban.Std() != 30*time.Minute {
		t.Errorf("ban = %v", c.Shield.Ban.Std())
	}
}

// Every pre-v2 top-level and nested key is an unknown field.
func TestParseRejectsPreV2Keys(t *testing.T) {
	for _, extra := range []string{
		"peers: []\n",
		"peers: {}\n",
		"routes: []\n",
		"listen: {}\n",
		"sip: {}\n",
		"network: {}\n",
		"webrtc: {}\n",
		"ring_timeout: 60s\n",
		"register_expires: 1h\n",
		"session_expires: 30m\n",
		"min_se: 90s\n",
		"peer_cooldown: 30s\n",
		"srv_cache_ttl: 5m\n",
		"max_concurrent_calls: 1\n",
		"shield: { peer_rate_limit: 1/s }\n",
		"shield: { auto_ban: { duration: 1h } }\n",
		"admin: { listen: 127.0.0.1:1, auth: {} }\n",
	} {
		err := parseErr(t, with(extra))
		if !strings.Contains(err, "unknown field") {
			t.Errorf("%q: error is not an unknown-field error:\n%s", extra, err)
		}
	}
	for _, c := range []struct{ old, new string }{
		{"public:\n  ip: 203.0.113.7", "public:\n  ip: 203.0.113.7\n  advertised_ip: 1.2.3.4"},
		{"edge:\n", "edge:\n  upstream: {}\n"},
		{"edge:\n", "edge:\n  transport: udp\n"},
	} {
		err := parseErr(t, replace(t, minimalYAML, c.old, c.new))
		if !strings.Contains(err, "unknown field") {
			t.Errorf("%q: not an unknown-field error:\n%s", c.new, err)
		}
	}
}

func TestParseUnknownFieldHasLine(t *testing.T) {
	err := parseErr(t, with("bogus: 1\n"))
	if !strings.Contains(err, "bogus") || !strings.Contains(err, "^") {
		t.Errorf("want a located unknown-field error, got:\n%s", err)
	}
}

func TestValidateErrors(t *testing.T) {
	adminHash := func(cost int) string {
		h, err := bcrypt.GenerateFromPassword([]byte("pw"), cost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	good := adminHash(10)
	cases := []struct{ name, src, want string }{
		{"no public", replace(t, minimalYAML, "public:\n  ip: 203.0.113.7\n", ""), "public.ip: required"},
		{"public bad ip", replace(t, minimalYAML, "203.0.113.7", "nope"), "public.ip"},
		{"public wildcard", replace(t, minimalYAML, "203.0.113.7", "0.0.0.0"), "unspecified"},
		{"bind wildcard", replace(t, minimalYAML, "  ip: 203.0.113.7", "  ip: 203.0.113.7\n  bind: \"::\""), "public.bind"},
		{"no private", replace(t, minimalYAML, "private:\n  ip: 10.77.0.2\n", ""), "private.ip: required"},
		{"private wildcard", replace(t, minimalYAML, "10.77.0.2", "0.0.0.0"), "private.ip"},
		{"private equals public", replace(t, minimalYAML, "10.77.0.2", "203.0.113.7"), "must differ from public.bind"},
		{"private equals bind", replace(t, minimalYAML, "  ip: 203.0.113.7", "  ip: 1.1.1.1\n  bind: 10.77.0.2"), "must differ from public.bind"},
		{"rtp low", with("rtp: 100-200\n"), "1024"},
		{"rtp no pair", with("rtp: 30001-30002\n"), "no RTP/RTCP pair"},
		{"rtp bad", with("rtp: nope\n"), "port range"},
		{"tls half", with("tls: { cert: /c.pem }\n"), "cert and key"},
		{"wss needs tls", replace(t, minimalYAML, "{ udp: 5060 }", "{ udp: 5060, wss: 443 }"), "required by edge.listen.wss"},
		{"remote admin needs tls", with("admin: { listen: 0.0.0.0:8080, allow_remote: true, password_hash: " + good + " }\n"), "required by admin.allow_remote"},
		{"no switch", replace(t, minimalYAML, "switch: [10.77.0.10:5060]", "switch: []"), "edge.switch: at least one"},
		{"switch hostname", replace(t, minimalYAML, "10.77.0.10:5060", "fs.example.com:5060"), "literal IP"},
		{"switch no port", replace(t, minimalYAML, "10.77.0.10:5060", "10.77.0.10"), "IP:port"},
		{"switch dup", replace(t, minimalYAML, "[10.77.0.10:5060]", "[10.77.0.10:5060, 10.77.0.10:5060]"), "listed twice"},
		{"switch is private socket", replace(t, minimalYAML, "10.77.0.10:5060", "10.77.0.2:5060"), "own private socket"},
		{"carrier port range", replace(t, minimalYAML, "edge:\n", "edge:\n  switch_carrier_port: 70000\n"), "switch_carrier_port"},
		{"no listen", replace(t, minimalYAML, "{ udp: 5060 }", "{}"), "edge.listen: at least one"},
		{"listen port", replace(t, minimalYAML, "{ udp: 5060 }", "{ udp: 70000 }"), "edge.listen.udp"},
		{"ws==wss", replace(t, minimalYAML, "{ udp: 5060 }", "{ ws: 443, wss: 443 }") + "tls: { cert: a, key: b }\n", "already used by edge.listen.ws"},
		{"carriers need udp", replace(t, minimalYAML, "{ udp: 5060 }", "{ ws: 8080 }\n  carriers: { a: 1.2.3.4 }"), "requires edge.listen.udp"},
		{"carrier bad name", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { \"a b\": 1.2.3.4 }"), "must match"},
		{"carrier bad host", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: \"bad_host!\" }"), "edge.carriers.a"},
		{"carrier bad port", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: \"1.2.3.4:99999\" }"), "bad port"},
		{"carrier bare v6 port", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: \"2001:db8::1:5060x\" }"), "edge.carriers.a"},
		{"carrier dup", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: 1.2.3.4, b: \"1.2.3.4:5060\" }"), "already used by edge.carriers.a"},
		{"carrier dup dns case", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: Sip.Example.com, b: sip.example.com. }"), "already used"},
		{"carrier is own socket", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: \"203.0.113.7:5060\" }"), "own public UDP socket"},
		{"carrier is switch", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: \"10.77.0.10:5060\" }"), "edge.switch node"},
		{"carrier unspecified", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: 0.0.0.0 }"), "unspecified"},
		{"carrier source wide", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carrier_sources: [10.0.0.0/7]"), "wider than /8"},
		{"carrier source v6 wide", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carrier_sources: [\"2001::/16\"]"), "wider than /32"},
		{"carrier source junk", replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carrier_sources: [nope]"), "edge.carrier_sources"},
		{"shield rate", with("shield: { rate_limit: nope }\n"), "shield.rate_limit"},
		{"shield carrier rate", with("shield: { carrier_rate_limit: 0/s }\n"), "shield.carrier_rate_limit"},
		{"shield ban", with("shield: { ban: -1s }\n"), "shield.ban"},
		{"admin listen", with("admin: { listen: nope, password_hash: " + good + " }\n"), "admin.listen"},
		{"admin remote without opt-in", with("admin: { listen: 0.0.0.0:8080, password_hash: " + good + " }\n"), "allow_remote"},
		{"admin no hash", with("admin: { listen: 127.0.0.1:8080 }\n"), "admin.password_hash"},
		{"admin low cost", with("admin: { listen: 127.0.0.1:8080, password_hash: " + adminHash(bcrypt.MinCost) + " }\n"), "below the minimum of 10"},
		{"allowed_hosts empty", with("admin: { listen: 127.0.0.1:8080, password_hash: " + good + ", allowed_hosts: [\"\"] }\n"), "admin.allowed_hosts[0]"},
		{"allowed_hosts port", with("admin: { listen: 127.0.0.1:8080, password_hash: " + good + ", allowed_hosts: [\"a.example:8080\"] }\n"), "must not carry a port"},
		{"allowed_hosts scheme", with("admin: { listen: 127.0.0.1:8080, password_hash: " + good + ", allowed_hosts: [\"https://a.example\"] }\n"), "bare host"},
		{"allowed_hosts wildcard", with("admin: { listen: 127.0.0.1:8080, password_hash: " + good + ", allowed_hosts: [\"*.example\"] }\n"), "wildcard"},
		{"allowed_hosts bracketed", with("admin: { listen: 127.0.0.1:8080, password_hash: " + good + ", allowed_hosts: [\"[::1]\"] }\n"), "brackets"},
		{"allowed_hosts dup", with("admin: { listen: 127.0.0.1:8080, password_hash: " + good + ", allowed_hosts: [A.example, a.example.] }\n"), "duplicate"},
		{"admin vs wss", replace(t, minimalYAML, "{ udp: 5060 }", "{ wss: 8443 }") + "tls: { cert: a, key: b }\nadmin: { listen: 203.0.113.7:8443, allow_remote: true, password_hash: " + good + " }\n", "already bound by edge.listen.wss"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := parseErr(t, tc.src); !strings.Contains(err, tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsEdgeCases(t *testing.T) {
	good, err := bcrypt.GenerateFromPassword([]byte("pw"), 10)
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"bare ipv6 carrier":     replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: \"2001:db8::1\" }"),
		"loopback admin":        with("admin: { listen: 127.0.0.1:8080, password_hash: " + string(good) + " }\n"),
		"remote admin with tls": with("tls: { cert: a, key: b }\nadmin: { listen: 0.0.0.0:8080, allow_remote: true, password_hash: " + string(good) + " }\n"),
		"allowed hosts":         with("admin: { listen: 127.0.0.1:8080, password_hash: " + string(good) + ", allowed_hosts: [sbc.example.net, 192.0.2.5, \"2001:db8::1\"] }\n"),
		"tls without wss":       with("tls: { cert: a, key: b }\n"),
		"carrier 4in6 source":   replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carrier_sources: [\"::ffff:10.0.0.1\"]"),
		"distinct switches":     replace(t, minimalYAML, "[10.77.0.10:5060]", "[10.77.0.10:5060, 10.77.0.10:5061]"),
	} {
		t.Run(name, func(t *testing.T) { mustParse(t, src) })
	}
}

func TestValidateAggregatesAllErrors(t *testing.T) {
	err := parseErr(t, "public: { ip: x }\nprivate: { ip: y }\nedge: { listen: {} }\n")
	for _, want := range []string{"public.ip", "private.ip", "edge.switch", "edge.listen"} {
		if !strings.Contains(err, want) {
			t.Errorf("missing %q in:\n%s", want, err)
		}
	}
}

func TestCarrierSource4in6MapsToIPv4(t *testing.T) {
	c := mustParse(t, replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carrier_sources: [\"::ffff:10.0.0.1\"]"))
	if got := c.Edge.carrierNets; len(got) != 1 || !got[0].Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("4in6 carrier source does not match 10.0.0.1: %v", got)
	}
}

func TestParseCarrierHost(t *testing.T) {
	for in, want := range map[string]struct {
		host string
		port int
	}{
		"sip.a.com":        {"sip.a.com", 5060},
		"SIP.A.com.:5080":  {"sip.a.com", 5080},
		"1.2.3.4":          {"1.2.3.4", 5060},
		"1.2.3.4:16060":    {"1.2.3.4", 16060},
		"[2001:db8::1]:70": {"2001:db8::1", 70},
		"2001:db8::1":      {"2001:db8::1", 5060},
	} {
		h, p, _, err := ParseCarrierHost(in)
		if err != nil || h != want.host || p != want.port {
			t.Errorf("%q = %q %d %v, want %q %d", in, h, p, err, want.host, want.port)
		}
	}
	for _, bad := range []string{"", "a:b:c", "-bad.com", "a..b", "host:0", "host:x", "[::1", "0.0.0.0", "under_score.com"} {
		if _, _, _, err := ParseCarrierHost(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseEnvExpansion(t *testing.T) {
	t.Setenv("FS_NODE", "10.77.0.10:5060")
	t.Setenv("PUB", "203.0.113.7")
	src := replace(t, minimalYAML, "10.77.0.10:5060", "\"${FS_NODE}\"")
	src = replace(t, src, "203.0.113.7", "${PUB}")
	c := mustParse(t, src)
	if c.Public.IP != "203.0.113.7" || c.Edge.Switch[0] != "10.77.0.10:5060" {
		t.Errorf("not expanded: %+v", c.Edge.Switch)
	}
}

func TestParseMissingEnvVarFails(t *testing.T) {
	if err := parseErr(t, replace(t, minimalYAML, "203.0.113.7", "${NOPE_UNSET_X}")); !strings.Contains(err, "NOPE_UNSET_X") {
		t.Errorf("error does not name the variable: %s", err)
	}
}

func TestParseEnvVarInCommentIsIgnored(t *testing.T) {
	mustParse(t, "# ${NOT_SET_ANYWHERE}\n"+minimalYAML)
}

func TestParseMalformedEnvRefFails(t *testing.T) {
	if err := parseErr(t, replace(t, minimalYAML, "203.0.113.7", "${A:-b}")); !strings.Contains(err, "malformed") {
		t.Errorf("got %s", err)
	}
	// ${123} is no longer special: it is malformed like any other.
	if err := parseErr(t, replace(t, minimalYAML, "203.0.113.7", "${1}")); !strings.Contains(err, "malformed") {
		t.Errorf("got %s", err)
	}
}

func TestParseEnvInTypedScalarIsParseError(t *testing.T) {
	t.Setenv("R", "30000-30999")
	if err := parseErr(t, with("rtp: ${R}\n")); !strings.Contains(err, "port range") {
		t.Errorf("got %s", err)
	}
}

func TestValidationErrorDoesNotEchoEnv(t *testing.T) {
	const sentinel = "sentinel-s3cr3t-value"
	t.Setenv("SECRET_X", sentinel)
	for name, src := range map[string]string{
		"public.ip":    replace(t, minimalYAML, "203.0.113.7", "${SECRET_X}"),
		"switch":       replace(t, minimalYAML, "10.77.0.10:5060", "${SECRET_X}"),
		"carrier":      replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: \"${SECRET_X}:99999\" }"),
		"carrier src":  replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carrier_sources: [\"${SECRET_X}\"]"),
		"shield":       with("shield: { rate_limit: \"${SECRET_X}\" }\n"),
		"admin hash":   with("admin: { listen: 127.0.0.1:8080, password_hash: \"${SECRET_X}\" }\n"),
		"admin listen": with("admin: { listen: \"${SECRET_X}\", password_hash: x }\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := parseErr(t, src); strings.Contains(err, sentinel) {
				t.Errorf("error echoes the expanded env value:\n%s", err)
			}
		})
	}
}

func TestParseErrorDoesNotLeakSecret(t *testing.T) {
	t.Setenv("PW", "hunter2-secret")
	err := parseErr(t, with("admin: { listen: 127.0.0.1:8080, password_hash: ${PW}, bogus: 1 }\n"))
	if strings.Contains(err, "hunter2-secret") {
		t.Errorf("parse error leaked the secret:\n%s", err)
	}
}

func TestParseQuotedScalars(t *testing.T) {
	src := `
public: { ip: "203.0.113.7" }
private: { ip: '10.77.0.2' }
rtp: "30000-30999"
edge:
  switch: ["10.77.0.10:5060"]
  listen: { udp: 5060 }
shield: { ban: "2h" }
`
	c := mustParse(t, src)
	if c.RTP.Min != 30000 || c.Shield.Ban.Std() != 2*time.Hour {
		t.Errorf("%+v", c)
	}
}

func TestNullSectionsDoNotPanic(t *testing.T) {
	for _, src := range []string{
		"", "public:\nprivate:\nedge:\n", minimalYAML + "tls:\n", minimalYAML + "admin:\n",
		replace(t, minimalYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers:\n    a:\n"),
		replace(t, minimalYAML, "[10.77.0.10:5060]", "[~]"),
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Parse panicked on %q: %v", src, r)
				}
			}()
			_, _ = Parse([]byte(src))
		}()
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freesbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path + ".missing"); err == nil {
		t.Error("missing file accepted")
	}
}

func TestValidateOpensNoFilesAndChecksNoLocality(t *testing.T) {
	// Non-existent cert paths and a public.ip that is not local both pass:
	// check binds nothing and opens nothing.
	mustParse(t, with("tls: { cert: /nonexistent/c.pem, key: /nonexistent/k.pem }\n"))
}
