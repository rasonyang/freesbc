// The Prometheus example rules in examples/prometheus/alerts.yml must name
// only the series internal/admin/metrics.go exports: a renamed metric or
// label would break an alert silently, promtool is not a build dependency,
// and a YAML parser is already one. The test parses the rule file, collects
// every freesbc_* identifier in each expr, including an explicit
// {__name__="freesbc_x"} selector, plus the label names its {...} matchers
// and by()/without()/on()/ignoring() clauses use, and checks them
// against the prometheus.NewDesc calls in the metrics source. A
// group_left()/group_right() label list belongs to the other side of the
// join and is not checked against freesbc_* series.
// reason="..." matcher values are checked against endReasonLabels in
// internal/edge/dialog.go.

package doccheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

const (
	alertsYAML = "examples/prometheus/alerts.yml"
	metricsGo  = "internal/admin/metrics.go"
	dialogGo   = "internal/edge/dialog.go"
)

// scrapeLabels are labels Prometheus attaches to every scraped series rather
// than the exporter declaring them; they are valid on any selector or
// grouping clause.
var scrapeLabels = map[string]bool{"job": true, "instance": true}

// alertRuleFile mirrors the parts of the Prometheus rule-file shape the test
// reads (https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/).
type alertRuleFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert       string            `yaml:"alert"`
			Expr        string            `yaml:"expr"`
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

var (
	// reMetricName finds a freesbc_* identifier; quoted label values are
	// stripped first, so a value that happens to look like a metric name is
	// not collected.
	reMetricName = regexp.MustCompile(`\bfreesbc_[a-zA-Z0-9_]*`)
	// reQuoted finds a PromQL double-quoted string literal (label values).
	reQuoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	// reSelector finds a {...} label matcher, with an optional metric name
	// before it (a bare {__name__="freesbc_x", ...} selector has none).
	reSelector = regexp.MustCompile(`(?:\b([a-zA-Z_][a-zA-Z0-9_]*)\s*)?\{([^{}]*)\}`)
	// reMatcher finds a label name in a =, !=, =~ or !~ matcher.
	reMatcher = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*"((?:[^"\\]|\\.)*)"`)
	// reGrouping finds the label list of a by(), without(), on(),
	// ignoring(), group_left() or group_right() clause, with the clause
	// keyword in submatch 1. by/without/on/ignoring labels must belong to
	// a freesbc_* metric of the same expr; group_left/group_right labels
	// belong to the join's other side and are skipped.
	reGrouping = regexp.MustCompile(`\b(by|without|on|ignoring|group_left|group_right)\s*\(([^)]*)\)`)
)

// metricLabels returns the variable label set of every freesbc_* series
// metrics.go describes, keyed by metric name.
func metricLabels(t *testing.T, path string) map[string]map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewDesc" {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "prometheus" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.HasPrefix(name, "freesbc_") {
			return true
		}
		labels := map[string]bool{}
		if comp, ok := call.Args[2].(*ast.CompositeLit); ok {
			for _, el := range comp.Elts {
				if l, ok := el.(*ast.BasicLit); ok {
					if v, err := strconv.Unquote(l.Value); err == nil {
						labels[v] = true
					}
				}
			}
		}
		out[name] = labels
		return true
	})
	if len(out) == 0 {
		t.Fatalf("%s: no prometheus.NewDesc(freesbc_*) calls found", path)
	}
	return out
}

// endReasons returns the label values endReasonLabels declares in
// dialog.go: the valid reason="..." values of freesbc_edge_calls_ended_total.
func endReasons(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || vs.Names[0].Name != "endReasonLabels" || len(vs.Values) == 0 {
				continue
			}
			comp, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, el := range comp.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if lit, ok := kv.Value.(*ast.BasicLit); ok {
					if v, err := strconv.Unquote(lit.Value); err == nil {
						out[v] = true
					}
				}
			}
		}
		return true
	})
	if len(out) == 0 {
		t.Fatalf("%s: no endReasonLabels values found", path)
	}
	return out
}

// validateAlertExpr verifies the freesbc_* names and labels of one expr
// and returns each failure, so regression tests can check negative cases.
func validateAlertExpr(alert, expr string, declared map[string]map[string]bool, reasons map[string]bool) []string {
	var errs []string
	errorf := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}
	stripped := reQuoted.ReplaceAllString(expr, `""`)
	used := map[string]bool{}
	for _, m := range reMetricName.FindAllString(stripped, -1) {
		used[m] = true
		if _, ok := declared[m]; !ok {
			errorf("%s: expr uses %s, which %s does not export", alert, m, metricsGo)
		}
	}
	// Label matchers: metric{label="value"}, or a bare {__name__="m", ...}
	// selector. Matchers are read from the unstripped expr so the label
	// values are intact. Only freesbc_* selectors are checked; labels of
	// other jobs' series (up{job=...}) are not ours.
	for _, sm := range reSelector.FindAllStringSubmatch(expr, -1) {
		metric, selector := sm[1], sm[2]
		// A __name__ matcher can carry the metric name itself. An explicit
		// equality is a metric use, so validate it too: the stripped scan
		// above cannot see inside the quoted value.
		for _, mm := range reMatcher.FindAllStringSubmatch(selector, -1) {
			if mm[1] == "__name__" && mm[2] == "=" {
				if v, err := strconv.Unquote(`"` + mm[3] + `"`); err == nil {
					metric = v
					if strings.HasPrefix(v, "freesbc_") {
						used[v] = true
						if _, ok := declared[v]; !ok {
							errorf("%s: expr uses %s, which %s does not export", alert, v, metricsGo)
						}
					}
				}
			}
		}
		if !strings.HasPrefix(metric, "freesbc_") {
			continue
		}
		for _, mm := range reMatcher.FindAllStringSubmatch(selector, -1) {
			label, op, raw := mm[1], mm[2], mm[3]
			if label == "__name__" || scrapeLabels[label] {
				continue
			}
			if !declared[metric][label] {
				errorf("%s: %s uses label %s, which %s does not declare on it", alert, metric, label, metricsGo)
				continue
			}
			// A literal reason="..." on the calls-ended counter must be a
			// reason the code can emit.
			if metric == "freesbc_edge_calls_ended_total" && label == "reason" && (op == "=" || op == "!=") {
				v, err := strconv.Unquote(`"` + raw + `"`)
				if err == nil && !reasons[v] {
					errorf("%s: %s uses reason=%q, which is not in endReasonLabels (%s)", alert, metric, v, dialogGo)
				}
			}
		}
	}
	// Grouping labels are written away from their metric; require each to be
	// a label of at least one freesbc_* metric in the expr, or a label
	// Prometheus attaches at scrape time (job, instance). group_left and
	// group_right label lists come from the join's other side, so they are
	// deliberately absent from this check.
	union := map[string]bool{}
	for m := range used {
		for l := range declared[m] {
			union[l] = true
		}
	}
	for _, gm := range reGrouping.FindAllStringSubmatch(stripped, -1) {
		if gm[1] == "group_left" || gm[1] == "group_right" {
			continue
		}
		for _, label := range strings.Split(gm[2], ",") {
			if label = strings.TrimSpace(label); label != "" && !union[label] && !scrapeLabels[label] {
				errorf("%s: grouping label %s is a label of no freesbc_* metric in the expr", alert, label)
			}
		}
	}
	return errs
}

// checkAlertExpr reports every validateAlertExpr failure on t.
func checkAlertExpr(t *testing.T, alert, expr string, declared map[string]map[string]bool, reasons map[string]bool) {
	t.Helper()
	for _, err := range validateAlertExpr(alert, expr, declared, reasons) {
		t.Error(err)
	}
}

func TestAlertExprJoinGroupLabels(t *testing.T) {
	declared := map[string]map[string]bool{
		"freesbc_example_total": {"plane": true},
	}
	for _, group := range []string{"group_left", "group_right"} {
		expr := `sum by (plane) (rate(freesbc_example_total[5m])) * on(instance) ` + group + `(nodename) node_uname_info`
		if errs := validateAlertExpr("Example", expr, declared, nil); len(errs) != 0 {
			t.Fatalf("valid %s join rejected: %v", group, errs)
		}
	}
}

func TestAlertExprExplicitMetricNameSelector(t *testing.T) {
	declared := map[string]map[string]bool{
		"freesbc_config_reload_failed": {},
	}
	valid := `{__name__="freesbc_config_reload_failed"} == 1`
	if errs := validateAlertExpr("Example", valid, declared, nil); len(errs) != 0 {
		t.Fatalf("valid explicit metric selector rejected: %v", errs)
	}
	invalid := `{__name__="freesbc_config_reload_failedd"} == 1`
	errs := validateAlertExpr("Example", invalid, declared, nil)
	if len(errs) != 1 || !strings.Contains(errs[0], "does not export") {
		t.Fatalf("unknown explicit metric selector errors = %v, want one does-not-export error", errs)
	}
}

func TestAlertRulesMetricNames(t *testing.T) {
	root := repoRoot(t)
	declared := metricLabels(t, filepath.Join(root, filepath.FromSlash(metricsGo)))
	reasons := endReasons(t, filepath.Join(root, filepath.FromSlash(dialogGo)))

	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(alertsYAML)))
	if err != nil {
		t.Fatal(err)
	}
	var rf alertRuleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		t.Fatalf("%s: %v", alertsYAML, err)
	}
	if len(rf.Groups) == 0 {
		t.Fatalf("%s: no groups", alertsYAML)
	}
	rules := 0
	for _, g := range rf.Groups {
		for i, r := range g.Rules {
			where := fmt.Sprintf("%s group %q rule %d (%s)", alertsYAML, g.Name, i, r.Alert)
			if r.Alert == "" {
				t.Errorf("%s group %q rule %d: no alert name", alertsYAML, g.Name, i)
			}
			if r.Expr == "" {
				t.Errorf("%s: no expr", where)
				continue
			}
			if r.Labels["severity"] == "" {
				t.Errorf("%s: no labels.severity", where)
			}
			if r.Annotations["summary"] == "" {
				t.Errorf("%s: no annotations.summary", where)
			}
			if r.Annotations["description"] == "" {
				t.Errorf("%s: no annotations.description", where)
			}
			checkAlertExpr(t, r.Alert, r.Expr, declared, reasons)
			rules++
		}
	}
	if rules == 0 {
		t.Fatalf("%s: no rules", alertsYAML)
	}
}
