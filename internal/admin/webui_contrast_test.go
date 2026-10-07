package admin

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestUITokenContrast computes WCAG 2.x contrast for every text/surface
// pairing the components in ui.css actually render, in both themes, from the
// values in tokens.css. Editing a token or a component recipe that drops a
// pair below its floor fails here rather than in an operator's browser.
//
// Model: OKLCH → linear sRGB (clipped), alpha composited in gamma sRGB as
// browsers do; color-mix(in oklch, A p, transparent) is A at alpha p, and
// color-mix(in oklch, A p, B) with achromatic B keeps A's hue.
//
// Not asserted, by decision (see docs/admin-ui.md, "Known trade-offs"):
// shadcn's --ring focus halo and --input border are below 3:1 non-text
// contrast in both themes. They are inherited unchanged for parity.
func TestUITokenContrast(t *testing.T) {
	b, err := webuiFS.ReadFile("webui/assets/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	tokens := parseLightDark(t, string(b))
	tokens["destructive-foreground"] = [2]okl{{1, 0, 0, 1}, {1, 0, 0, 1}}

	for mode, name := range []string{"light", "dark"} {
		tk := func(n string) okl {
			v, ok := tokens[n]
			if !ok {
				t.Fatalf("token --%s not found in tokens.css", n)
			}
			return v[mode]
		}
		bg := tk("background").rgb()
		card := tk("card").rgb()
		// Text on a status tint: light pulls the tone 15% toward the
		// foreground (ui.css .badge, .alert, .banner); dark uses it bare.
		ink := func(n string) srgb {
			if mode == 0 {
				return mixOKLCH(tk(n), 0.85, tk("foreground")).rgb()
			}
			return tk(n).rgb()
		}
		destructiveBtn := tk("destructive")
		if mode == 1 {
			destructiveBtn = destructiveBtn.alpha(0.6) // dark:bg-destructive/60
		}

		type pair struct {
			label  string
			fg, bg srgb
			min    float64
		}
		pairs := []pair{
			{"foreground on background", tk("foreground").rgb(), bg, 4.5},
			{"card-foreground on card", tk("card-foreground").rgb(), card, 4.5},
			{"muted-foreground on background", tk("muted-foreground").rgb(), bg, 4.5},
			{"muted-foreground on card", tk("muted-foreground").rgb(), card, 4.5},
			{"muted-foreground on table head", tk("muted-foreground").rgb(), tk("muted").alpha(0.5).rgb().over(card), 4.5},
			{"primary-foreground on primary", tk("primary-foreground").rgb(), tk("primary").rgb(), 4.5},
			{"secondary-foreground on secondary", tk("secondary-foreground").rgb(), tk("secondary").rgb(), 4.5},
			{"destructive-foreground on destructive button", tk("destructive-foreground").rgb(), destructiveBtn.rgb().over(bg), 4.5},
			{"destructive ink on banner", ink("destructive"), tk("destructive").alpha(0.10).rgb().over(bg), 4.5},
			{"destructive ink on destructive alert", ink("destructive"), mixOKLCH(tk("destructive"), 0.06, tk("card")).rgb(), 4.5},
		}
		for _, s := range []string{"success", "warning", "info", "destructive"} {
			pairs = append(pairs,
				pair{s + " on card", tk(s).rgb(), card, 4.5},
				pair{s + " ink on its 12% badge", ink(s), tk(s).alpha(0.12).rgb().over(card), 4.5},
			)
		}
		// Config diff rows (.diff-line): the badge recipe on the card, plus
		// muted context text on the card.
		for _, s := range []string{"success", "destructive"} {
			pairs = append(pairs, pair{"diff " + s + " line", ink(s), tk(s).alpha(0.12).rgb().over(card), 4.5})
		}
		for _, s := range []string{"primary", "warning", "destructive"} {
			pairs = append(pairs, pair{"meter " + s + " fill on its 20% track", tk(s).rgb(), tk(s).alpha(0.2).rgb().over(card), 3})
		}
		for _, p := range pairs {
			if r := contrast(p.fg, p.bg); r < p.min {
				t.Errorf("%s: %s = %.2f:1, want ≥ %.1f:1", name, p.label, r, p.min)
			}
		}
	}
}

// okl is an OKLCH colour with alpha.
type okl struct{ L, C, H, A float64 }

// srgb is a gamma-encoded sRGB colour with alpha, components in [0,1].
type srgb struct{ R, G, B, A float64 }

func (c okl) alpha(a float64) okl { c.A = a; return c }

func (c okl) rgb() srgb {
	a := c.C * math.Cos(c.H*math.Pi/180)
	b := c.C * math.Sin(c.H*math.Pi/180)
	l := math.Pow(c.L+0.3963377774*a+0.2158037573*b, 3)
	m := math.Pow(c.L-0.1055613458*a-0.0638541728*b, 3)
	s := math.Pow(c.L-0.0894841775*a-1.2914855480*b, 3)
	enc := func(x float64) float64 {
		x = math.Min(1, math.Max(0, x))
		if x <= 0.0031308 {
			return 12.92 * x
		}
		return 1.055*math.Pow(x, 1/2.4) - 0.055
	}
	return srgb{
		enc(4.0767416621*l - 3.3077115913*m + 0.2309699292*s),
		enc(-1.2684380046*l + 2.6097574011*m - 0.3413193965*s),
		enc(-0.0041960863*l - 0.7034186147*m + 1.7076147010*s),
		c.A,
	}
}

// over composites c onto an opaque backdrop.
func (c srgb) over(b srgb) srgb {
	return srgb{c.A*c.R + (1-c.A)*b.R, c.A*c.G + (1-c.A)*b.G, c.A*c.B + (1-c.A)*b.B, 1}
}

func mixOKLCH(a okl, p float64, b okl) okl {
	return okl{p*a.L + (1-p)*b.L, p*a.C + (1-p)*b.C, a.H, 1}
}

func contrast(fg, bg srgb) float64 {
	if fg.A < 1 {
		fg = fg.over(bg)
	}
	lum := func(c srgb) float64 {
		lin := func(x float64) float64 {
			if x <= 0.04045 {
				return x / 12.92
			}
			return math.Pow((x+0.055)/1.055, 2.4)
		}
		return 0.2126*lin(c.R) + 0.7152*lin(c.G) + 0.0722*lin(c.B)
	}
	hi, lo := lum(fg), lum(bg)
	if lo > hi {
		hi, lo = lo, hi
	}
	return (hi + 0.05) / (lo + 0.05)
}

var (
	lightDarkRe = regexp.MustCompile(`--([\w-]+):\s*light-dark\((oklch\([^)]*\)),\s*(oklch\([^)]*\))\)`)
	oklchRe     = regexp.MustCompile(`^oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(?:/\s*([\d.]+)(%?))?\s*\)$`)
)

func parseLightDark(t *testing.T, css string) map[string][2]okl {
	t.Helper()
	out := map[string][2]okl{}
	for _, m := range lightDarkRe.FindAllStringSubmatch(css, -1) {
		out[m[1]] = [2]okl{parseOKLCH(t, m[2]), parseOKLCH(t, m[3])}
	}
	if len(out) < 20 {
		t.Fatalf("parsed only %d light-dark() tokens from tokens.css", len(out))
	}
	return out
}

func parseOKLCH(t *testing.T, s string) okl {
	t.Helper()
	m := oklchRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		t.Fatalf("unparseable colour %q", s)
	}
	f := func(x string) float64 {
		v, err := strconv.ParseFloat(x, 64)
		if err != nil {
			t.Fatalf("colour %q: %v", s, err)
		}
		return v
	}
	c := okl{f(m[1]), f(m[2]), f(m[3]), 1}
	if m[4] != "" {
		c.A = f(m[4])
		if m[5] == "%" {
			c.A /= 100
		}
	}
	return c
}
