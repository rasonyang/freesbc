// Package doccheck keeps the code citations in the Markdown docs valid.
//
// The docs cite code by symbol and file, never by line number, because line
// numbers rot with every edit. This package has no non-test code; it is a
// test-only package so that `go test ./...` runs the check.
//
// Citation grammar (what the check enforces):
//
//  1. No line numbers. `path.go:N`, `path.go:N-M` and `path.go:N,M` are
//     violations, backticked or not. So is a backticked shorthand line
//     reference, a span that is exactly `:N` or `:N-M` (see isShorthand).
//  2. Symbol citation, in one of two forms. Each may span one line break
//     (the whitespace may hold a single newline plus indentation).
//     a. A backtick span holding a symbol, optional whitespace, "(", then a
//     backticked .go path, then ")", ";" or ",":
//     `confirm` (`internal/edge/dialog.go`)
//     `allocateRTP` (`edge/media.go`; a caller's leg)
//     b. Inside a parenthetical: a backtick span, ",", optional whitespace,
//     then a backticked .go path, then ")", ";" or ",":
//     (`confirm`, `internal/edge/dialog.go`)
//     (`allocateRTP`, `edge/media.go`; a caller's leg)
//     (`respToSwitch`, `hideResponse`, `hide.go`)
//     Only the span directly before the path is the symbol. In form b a span
//     that is itself a path or is not symbol-shaped (spaces, "/", "=", ...)
//     is not taken as a symbol and is skipped; in form a it is a violation.
//     The symbol is Name, Name(args), Recv.Name, pkg.Name or Type.Field. It
//     must be declared at top level in the cited file: a func, type, var or
//     const Name; a method Name (bare: any receiver; Recv.Name: that receiver
//     type, pointer or not); pkg.Name with pkg the file's package name; or
//     Type.Field with Type a struct declared there that has the field (an
//     interface method also counts as a field).
//  3. Every backticked .go path must resolve to exactly one .go file in the
//     repo: a repo-relative path, or a suffix of one on a "/" boundary
//     (edge/media.go, dialog.go). An exact match wins over suffix matches.
//     Spans with "*", spaces or other non-path characters are ignored.
//  4. External citations: `Sym` (sipgo `sip/transaction_server_tx.go`),
//     (`Sym`, sipgo `sip/transaction_server_tx.go`) or sipgo `path.go` (the
//     word sipgo immediately before the path span). The
//     path is resolved inside the github.com/emiago/sipgo module directory
//     (found with `go list -m`), and rules 2 and 3 apply there.
//
// Lines inside fenced code blocks are not checked. Reports are doc:line,
// the line of the path span (of the line-number text for rule 1).
//
// Scope: README.md, CLAUDE.md and every *.md under docs/ except docs/notes/.
// The environment variable DOCCHECK_FILES (comma-separated paths, absolute or
// relative to the repo root) replaces that list when set, for checking a
// partial copy of a doc.
package doccheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type violation struct {
	line     int
	citation string
	rule     string
	reason   string
}

// resolver maps a cited path to one .go file under dir.
type resolver struct {
	dir   string
	files []string // slash-separated, relative to dir, sorted
}

func newResolver(dir string) (*resolver, error) {
	r := &resolver{dir: dir}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == dir {
				return nil
			}
			// Hidden directories (.git, a .claude/worktrees checkout) and
			// nested modules hold copies or other code, not this module.
			switch name := d.Name(); {
			case strings.HasPrefix(name, "."), name == "vendor", name == "testdata", name == "node_modules":
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			r.files = append(r.files, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(r.files)
	return r, err
}

// resolve returns the one file cite names, or the candidates when it names
// none (empty) or several.
func (r *resolver) resolve(cite string) (string, []string) {
	var suffix []string
	for _, f := range r.files {
		if f == cite {
			return f, nil
		}
		if strings.HasSuffix(f, "/"+cite) {
			suffix = append(suffix, f)
		}
	}
	if len(suffix) == 1 {
		return suffix[0], nil
	}
	return "", suffix
}

// decls is what a Go file declares at top level.
type decls struct {
	pkg     string
	top     map[string]bool            // func, type, var, const names
	methods map[string]map[string]bool // method name -> receiver types
	fields  map[string]map[string]bool // struct or interface type -> members
}

func (d *decls) has(sym string) bool {
	a, b, dotted := strings.Cut(sym, ".")
	if !dotted {
		return d.top[a] || len(d.methods[a]) > 0
	}
	if a == d.pkg && d.top[b] {
		return true
	}
	return d.methods[b][a] || d.fields[a][b]
}

var (
	declMu    sync.Mutex
	declCache = map[string]*decls{}
)

func parseDecls(path string) (*decls, error) {
	declMu.Lock()
	defer declMu.Unlock()
	if d, ok := declCache[path]; ok {
		return d, nil
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	d := &decls{
		pkg:     f.Name.Name,
		top:     map[string]bool{},
		methods: map[string]map[string]bool{},
		fields:  map[string]map[string]bool{},
	}
	for _, decl := range f.Decls {
		switch x := decl.(type) {
		case *ast.FuncDecl:
			if x.Recv == nil || len(x.Recv.List) == 0 {
				d.top[x.Name.Name] = true
				continue
			}
			recv := recvName(x.Recv.List[0].Type)
			if d.methods[x.Name.Name] == nil {
				d.methods[x.Name.Name] = map[string]bool{}
			}
			d.methods[x.Name.Name][recv] = true
		case *ast.GenDecl:
			for _, spec := range x.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					d.top[s.Name.Name] = true
					d.fields[s.Name.Name] = members(s.Type)
				case *ast.ValueSpec:
					for _, n := range s.Names {
						d.top[n.Name] = true
					}
				}
			}
		}
	}
	declCache[path] = d
	return d, nil
}

// recvName returns the receiver's type name without pointer or type params.
func recvName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvName(x.X)
	case *ast.IndexExpr:
		return recvName(x.X)
	case *ast.IndexListExpr:
		return recvName(x.X)
	case *ast.ParenExpr:
		return recvName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return ""
}

func members(t ast.Expr) map[string]bool {
	m := map[string]bool{}
	var list *ast.FieldList
	switch x := t.(type) {
	case *ast.StructType:
		list = x.Fields
	case *ast.InterfaceType:
		list = x.Methods
	}
	if list == nil {
		return m
	}
	for _, f := range list.List {
		if len(f.Names) == 0 {
			if n := recvName(f.Type); n != "" {
				m[n] = true
			}
			continue
		}
		for _, n := range f.Names {
			m[n.Name] = true
		}
	}
	return m
}

// checker holds the two places a citation can resolve into.
type checker struct {
	repo  *resolver
	sipgo func() (*resolver, error) // lazy: only when a sipgo citation exists
}

var (
	reSpan       = regexp.MustCompile("`([^`]+)`")
	reLineCite   = regexp.MustCompile(`[A-Za-z0-9_./-]+\.go:(?:[ \t]*\n[ \t]*)?[0-9]+(?:[-,][0-9]+)*`)
	rePathSpan   = regexp.MustCompile(`^[A-Za-z0-9_./-]+\.go$`)
	reShorthand  = regexp.MustCompile(`^:([0-9]+)(?:-([0-9]+))?$`)
	reSymbol     = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)(?:\(.*\))?$`)
	reSipgoSym   = regexp.MustCompile("`([^`\\n]+)`[ \\t]*(?:\\n[ \\t]*)?\\(\\s*sipgo\\s*$")
	reSipgoComma = regexp.MustCompile("`([^`\\n]+)`,[ \\t]*(?:\\n[ \\t]*)?sipgo\\s*$")
	reSipgoBare  = regexp.MustCompile(`\bsipgo\s*$`)
	reSymBefore  = regexp.MustCompile("`([^`\\n]+)`[ \\t]*(?:\\n[ \\t]*)?\\(\\s*$")
	reSymComma   = regexp.MustCompile("`([^`\\n]+)`,[ \\t]*(?:\\n[ \\t]*)?$")
	reFenceStart = regexp.MustCompile("^\\s*(```|~~~)")
)

// portShorthand lists the single port numbers that may stand alone as `:N`.
var portShorthand = map[int]bool{
	0: true, 53: true, 80: true, 443: true, 5060: true, 5061: true, 5062: true,
	5080: true, 8080: true, 8443: true, 9090: true, 9100: true,
}

// isShorthand reports whether a span like `:620` or `:137-140` is a line
// reference inherited from the previous file. A single number is a line
// reference unless it is a well-known port (portShorthand); a range is one
// only when it spans fewer than 50 numbers, so a port range such as
// `:20000-29999` passes.
func isShorthand(span string) bool {
	m := reShorthand.FindStringSubmatch(span)
	if m == nil {
		return false
	}
	n, _ := strconv.Atoi(m[1])
	if m[2] == "" {
		return !portShorthand[n]
	}
	hi, _ := strconv.Atoi(m[2])
	return hi-n < 50
}

// checkDoc returns the violations of one document. It scans the whole text
// (fenced lines blanked) so a citation may span a line break; reports carry
// the line of the offending text.
func (c *checker) checkDoc(contents string) []violation {
	lines := strings.Split(contents, "\n")
	inFence := false
	for i, line := range lines {
		if reFenceStart.MatchString(line) {
			inFence = !inFence
			lines[i] = ""
		} else if inFence {
			lines[i] = ""
		}
	}
	text := strings.Join(lines, "\n")
	lineAt := func(off int) int { return 1 + strings.Count(text[:off], "\n") }

	var out []violation
	for _, loc := range reLineCite.FindAllStringIndex(text, -1) {
		out = append(out, violation{lineAt(loc[0]), text[loc[0]:loc[1]], "line-number", "line-number citation; cite a symbol and file instead"})
	}
	off := 0
	for _, line := range lines {
		for _, loc := range reSpan.FindAllStringSubmatchIndex(line, -1) {
			start, end := off+loc[0], off+loc[1]
			span := line[loc[2]:loc[3]]
			n := lineAt(start)
			if isShorthand(span) {
				out = append(out, violation{n, "`" + span + "`", "line-number", "shorthand line reference; cite a symbol and file instead"})
				continue
			}
			if !rePathSpan.MatchString(span) {
				continue
			}
			out = append(out, c.checkPath(n, text, start, end, span)...)
		}
		off += len(line) + 1
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].line < out[j].line })
	return out
}

// checkPath checks the backticked .go path span at text[start:end].
func (c *checker) checkPath(n int, text string, start, end int, path string) []violation {
	prefix := text[max(0, start-400):start]
	var sym string
	external, comma := false, false
	if m := reSipgoSym.FindStringSubmatch(prefix); m != nil {
		sym, external = m[1], true
	} else if m := reSipgoComma.FindStringSubmatch(prefix); m != nil {
		sym, external, comma = m[1], true, true
	} else if reSipgoBare.MatchString(prefix) {
		external = true
	} else if m := reSymBefore.FindStringSubmatch(prefix); m != nil {
		sym = m[1]
	} else if m := reSymComma.FindStringSubmatch(prefix); m != nil {
		sym, comma = m[1], true
	}
	// A symbol citation needs ")", ";" or "," right after the path span.
	if sym != "" && (end >= len(text) || !strings.ContainsRune(");,", rune(text[end]))) {
		sym = ""
	}
	if strings.HasSuffix(sym, ".go") {
		sym = "" // a path followed by a path, not a symbol
	}
	// The comma form only takes symbol-shaped spans; anything else is prose.
	if comma && !reSymbol.MatchString(sym) {
		sym = ""
	}
	cite := "`" + path + "`"
	if sym != "" && comma {
		cite = "`" + sym + "`, " + cite
	} else if sym != "" {
		cite = "`" + sym + "` (" + cite + ")"
	}

	r, where := c.repo, "the repo"
	if external {
		var err error
		if r, err = c.sipgo(); err != nil {
			return []violation{{n, cite, "path", "cannot locate the sipgo module: " + err.Error()}}
		}
		where = "the sipgo module"
	}
	file, cands := r.resolve(path)
	if file == "" {
		if len(cands) == 0 {
			return []violation{{n, cite, "path", "no .go file " + path + " in " + where}}
		}
		return []violation{{n, cite, "path", "ambiguous path " + path + " in " + where + ": " + strings.Join(cands, ", ")}}
	}
	if sym == "" {
		return nil
	}
	m := reSymbol.FindStringSubmatch(sym)
	if m == nil {
		return []violation{{n, cite, "symbol", "not a symbol (want Name, Name(args), Recv.Name, pkg.Name or Type.Field)"}}
	}
	d, err := parseDecls(filepath.Join(r.dir, filepath.FromSlash(file)))
	if err != nil {
		return []violation{{n, cite, "symbol", "cannot parse " + file + ": " + err.Error()}}
	}
	if !d.has(m[1]) {
		return []violation{{n, cite, "symbol", "symbol " + m[1] + " not declared in " + file}}
	}
	return nil
}

func repoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// docFiles lists the documents to check as repo-relative or given paths.
func docFiles(t testing.TB, root string) []string {
	t.Helper()
	if env := os.Getenv("DOCCHECK_FILES"); env != "" {
		var out []string
		for _, p := range strings.Split(env, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	out := []string{"README.md", "CLAUDE.md"}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "docs/notes" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".md") {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func sipgoResolver(root string) func() (*resolver, error) {
	return sync.OnceValues(func() (*resolver, error) {
		cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/emiago/sipgo")
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list -m github.com/emiago/sipgo: %w", err)
		}
		dir := strings.TrimSpace(string(out))
		if dir == "" {
			return nil, fmt.Errorf("go list -m github.com/emiago/sipgo printed no directory (module cache missing?)")
		}
		return newResolver(dir)
	})
}

func TestDocCitations(t *testing.T) {
	root := repoRoot(t)
	repo, err := newResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	c := &checker{repo: repo, sipgo: sipgoResolver(root)}
	for _, doc := range docFiles(t, root) {
		p := doc
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s: %v", doc, err)
			continue
		}
		for _, v := range c.checkDoc(string(b)) {
			t.Errorf("%s:%d: %s: %s", doc, v.line, v.citation, v.reason)
		}
	}
}

// --- tests of the checker itself ---

const fixtureSrc = `package sample

type Dialog struct {
	callID string
	Leg    int
}

type Iface interface{ Close() error }

const MaxThing = 3

var defaultThing = 1

func confirm() {}

func (d *Dialog) End(reason string) {}

func (Dialog) value() {}
`

// testChecker builds a repo of two files named dialog.go (so the bare name
// is ambiguous) and one unique file, plus a fake sipgo module.
func testChecker(t *testing.T) *checker {
	t.Helper()
	root, sipgoRoot := t.TempDir(), t.TempDir()
	write := func(base, rel, src string) {
		p := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(root, "internal/edge/dialog.go", fixtureSrc)
	write(root, "internal/media/dialog.go", "package media\n\nfunc Other() {}\n")
	write(root, "internal/edge/media.go", "package edge\n\nfunc allocateRTP() {}\n")
	write(sipgoRoot, "sip/tx.go", "package sip\n\ntype ServerTx struct{}\n\nfunc (tx *ServerTx) TerminateGracefully() {}\n")
	repo, err := newResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := newResolver(sipgoRoot)
	if err != nil {
		t.Fatal(err)
	}
	return &checker{repo: repo, sipgo: func() (*resolver, error) { return sg, nil }}
}

func rules(vs []violation) string {
	var parts []string
	for _, v := range vs {
		parts = append(parts, v.rule)
	}
	return strings.Join(parts, ",")
}

func TestCheckerLineNumbers(t *testing.T) {
	c := testChecker(t)
	for _, doc := range []string{
		"see `internal/edge/dialog.go:20`",
		"see internal/edge/dialog.go:20-36 here",
		"see `edge/dialog.go:448,487`",
		"`confirm` (`internal/edge/dialog.go`) and `:620`",
		"range `:137-140` too",
	} {
		if vs := c.checkDoc(doc); !strings.Contains(rules(vs), "line-number") {
			t.Errorf("%q: want a line-number violation, got %v", doc, vs)
		}
	}
}

func TestCheckerPortsNotShorthand(t *testing.T) {
	c := testChecker(t)
	doc := "listen on `:0`, `:5060`, `:5061` and `:20000-29999`, or `private.ip:5060`"
	if vs := c.checkDoc(doc); len(vs) != 0 {
		t.Errorf("ports flagged: %v", vs)
	}
}

func TestCheckerValidSymbols(t *testing.T) {
	c := testChecker(t)
	for _, doc := range []string{
		"`confirm` (`internal/edge/dialog.go`)",
		"`End` (`internal/edge/dialog.go`; the first caller wins)",
		"`Dialog.End` (`internal/edge/dialog.go`)",
		"`Dialog.value` (`edge/dialog.go`, more text)",
		"`sample.MaxThing` (`internal/edge/dialog.go`)",
		"`Dialog.callID` (`internal/edge/dialog.go`)",
		"`Iface.Close` (`internal/edge/dialog.go`)",
		"`confirm()` (`internal/edge/dialog.go`)",
		"`End(reason)` (`internal/edge/dialog.go`)",
		"`defaultThing` (`internal/edge/dialog.go`)",
		"`allocateRTP` (`edge/media.go`; a caller's leg)",
		"`ServerTx.TerminateGracefully` (sipgo `sip/tx.go`)",
		"sipgo `tx.go` and `edge/media.go`",
	} {
		if vs := c.checkDoc(doc); len(vs) != 0 {
			t.Errorf("%q: unexpected violations %v", doc, vs)
		}
	}
}

func TestCheckerBadSymbols(t *testing.T) {
	c := testChecker(t)
	for _, doc := range []string{
		"`renamedAway` (`internal/edge/dialog.go`)",
		"`Dialog.Missing` (`internal/edge/dialog.go`)",
		"`Other.End` (`internal/edge/dialog.go`)",
		"`media.Other` (`internal/edge/dialog.go`)",
		"`allocateRTP` (`internal/edge/dialog.go`)", // moved to media.go
		"`confirm` (`internal/edge/media.go`)",
		"`NoSuch` (sipgo `sip/tx.go`)",
		"`confirm` (`sip/tx.go`)", // repo path that only exists in sipgo
		"`not a symbol` (`internal/edge/dialog.go`)",
	} {
		vs := c.checkDoc(doc)
		if len(vs) != 1 || (vs[0].rule != "symbol" && vs[0].rule != "path") {
			t.Errorf("%q: want one symbol violation, got %v", doc, vs)
		}
	}
}

func TestCheckerPaths(t *testing.T) {
	c := testChecker(t)
	vs := c.checkDoc("a `internal/edge/nope.go` b")
	if len(vs) != 1 || !strings.Contains(vs[0].reason, "no .go file") {
		t.Errorf("missing path: %v", vs)
	}
	vs = c.checkDoc("a `dialog.go` b")
	if len(vs) != 1 || !strings.Contains(vs[0].reason, "ambiguous") ||
		!strings.Contains(vs[0].reason, "edge/dialog.go") || !strings.Contains(vs[0].reason, "media/dialog.go") {
		t.Errorf("ambiguous path: %v", vs)
	}
	if vs := c.checkDoc("a `edge/dialog.go` b and `media.go` and `internal/*_test.go` and `go.mod`"); len(vs) != 0 {
		t.Errorf("unexpected: %v", vs)
	}
	if vs := c.checkDoc("```\ninternal/edge/dialog.go:20\n```\n"); len(vs) != 0 {
		t.Errorf("fenced block checked: %v", vs)
	}
}

func TestCheckerCommaForm(t *testing.T) {
	c := testChecker(t)
	for _, doc := range []string{
		"(`confirm`, `internal/edge/dialog.go`)",
		"(`allocateRTP`, `edge/media.go`; a caller's leg)",
		"(`End`, `edge/dialog.go`, more text)",
		"(`Dialog.End`,   `edge/dialog.go`)",
		"(`confirm`, `End`, `edge/dialog.go`)", // only the span before the path
		"(`ServerTx.TerminateGracefully`, sipgo `sip/tx.go`)",
		"(`a b`, `edge/dialog.go`)",           // not symbol-shaped: just a path
		"(`x/y`, `edge/dialog.go`)",           // not symbol-shaped
		"(`edge/media.go`, `edge/dialog.go`)", // a path before a path
		"(`k=v`, `edge/dialog.go`)",
	} {
		if vs := c.checkDoc(doc); len(vs) != 0 {
			t.Errorf("%q: unexpected violations %v", doc, vs)
		}
	}
	for _, doc := range []string{
		"(`renamedAway`, `internal/edge/dialog.go`)",
		"(`allocateRTP`, `internal/edge/dialog.go`)",
		"(`confirm`, `internal/edge/media.go`)",
		"(`NoSuch`, sipgo `sip/tx.go`)",
		"(`confirm`, `End`, `edge/media.go`)", // End is the checked symbol
	} {
		vs := c.checkDoc(doc)
		if len(vs) != 1 || vs[0].rule != "symbol" {
			t.Errorf("%q: want one symbol violation, got %v", doc, vs)
		}
	}
}

func TestCheckerLineBreaks(t *testing.T) {
	c := testChecker(t)
	for _, doc := range []string{
		"text `confirm`\n(`internal/edge/dialog.go`) more",
		"text `confirm`\n   (`internal/edge/dialog.go`) more",
		"text (`confirm`,\n   `internal/edge/dialog.go`) more",
		"text (`ServerTx.TerminateGracefully`,\n  sipgo `sip/tx.go`) more",
		"text `ServerTx.TerminateGracefully`\n(sipgo `sip/tx.go`)",
	} {
		if vs := c.checkDoc(doc); len(vs) != 0 {
			t.Errorf("%q: unexpected violations %v", doc, vs)
		}
	}
	for _, doc := range []string{
		"text `renamedAway`\n(`internal/edge/dialog.go`) more",
		"text (`renamedAway`,\n  `internal/edge/dialog.go`) more",
	} {
		vs := c.checkDoc(doc)
		if len(vs) != 1 || vs[0].rule != "symbol" {
			t.Errorf("%q: want one symbol violation, got %v", doc, vs)
			continue
		}
		if vs[0].line != 2 {
			t.Errorf("%q: reported at line %d, want 2", doc, vs[0].line)
		}
	}
	// A blank line ends the paragraph: no citation across it.
	if vs := c.checkDoc("`renamedAway`\n\n(`internal/edge/dialog.go`)"); len(vs) != 0 {
		t.Errorf("citation across a blank line: %v", vs)
	}
	// A line-number citation split across lines is still caught.
	vs := c.checkDoc("see `x`\ninternal/edge/dialog.go:\n  20 for more")
	if len(vs) != 1 || vs[0].rule != "line-number" || vs[0].line != 2 {
		t.Errorf("split line-number citation: %v", vs)
	}
	// Fenced blocks stay skipped and do not shift reported lines.
	vs = c.checkDoc("```\na\n```\n`renamedAway` (`internal/edge/dialog.go`)")
	if len(vs) != 1 || vs[0].line != 4 {
		t.Errorf("line after fence: %v", vs)
	}
}
