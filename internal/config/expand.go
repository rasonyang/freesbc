package config

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// envRef matches ${VAR_NAME} — the only supported reference syntax. Anything
// else that merely looks like a "${" reference (e.g. bash-style
// ${VAR:-default}) is rejected rather than silently passed through as a
// literal.
var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// numericGroupRef matches ${123} — a regexp replacement group reference,
// not an env variable (a digit-led name can never be a valid env var). Such
// spans are left verbatim so route transforms can use ${N} next to literal
// digits (e.g. "${1}000"); they are neither expanded nor flagged malformed.
var numericGroupRef = regexp.MustCompile(`\$\{[0-9]+\}`)

// expandEnv walks a freshly unmarshalled Config and expands ${VAR}
// references in every exported string field — including slices, maps, and
// nested structs/pointers — so fields added in later milestones are covered
// automatically without touching this file again.
//
// Only fields whose Go type is string are expanded. Typed scalars (Duration,
// PortRange, SIPListen, HostPort) and ints/bools are decoded by the strict
// YAML step, before expansion runs, so `ring_timeout: ${RT}` is a parse error
// ("invalid duration"), not an expanded value.
//
// A field tagged `env:"-"` is never expanded: routes[].transform.to is a
// regexp replacement template, where ${name} names a capture group, not an
// environment variable.
//
// Every substitution is recorded on c so validation errors can be redacted
// (see envRedaction): a validation message must never echo an expanded
// environment value.
//
// It must run after the strict YAML unmarshal (so syntax/unknown-key errors
// report the user's real file, with no secrets in them) and before
// withDefaults/validate (so validation sees the final, expanded values).
//
// Expanded environment values are never re-scanned for further ${...}
// references: a secret that happens to contain "${" is left verbatim.
func expandEnv(c *Config) error {
	e := &envExpander{seenMissing: map[string]bool{}}
	e.walk(reflect.ValueOf(c), "config")
	c.envRedact = e.redact
	if len(e.malformed) > 0 {
		return fmt.Errorf("malformed ${...} reference in config: %s", strings.Join(e.malformed, "; "))
	}
	if len(e.missing) > 0 {
		return fmt.Errorf("undefined environment variable(s) referenced in config: %v", e.missing)
	}
	return nil
}

type envExpander struct {
	missing     []string
	malformed   []string
	seenMissing map[string]bool
	redact      envRedaction
}

// envRedaction remembers what expansion put into the Config, so text built
// from the expanded values (validation errors) can be mapped back to what the
// operator wrote. The zero value redacts nothing.
type envRedaction struct {
	// fields maps each expanded field's final value to its template, e.g.
	// "10.1.2.3:5060" -> "${FS_ADDR}:5060".
	fields map[string]string
	// values maps each substituted environment value to its variable name.
	values map[string]string
}

// tainted reports whether value is the final value of a field that ${VAR}
// expansion changed.
func (r envRedaction) tainted(value string) bool {
	_, ok := r.fields[value]
	return ok
}

// args returns a copy of fmt args with every string and error redacted by
// apply. Validation formats come from this package and never contain a
// value; only their arguments can carry an expanded one, so redacting the
// arguments leaves the rest of each message intact. Other types (numbers,
// durations) are passed through unchanged: only string fields are
// expanded, and converting them would break verbs such as %d.
func (r envRedaction) args(args []any) []any {
	if len(r.fields) == 0 {
		return args
	}
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			out[i] = r.apply(v)
		case error:
			out[i] = r.apply(v.Error())
		default:
			out[i] = a
		}
	}
	return out
}

// detail returns err for display, unless value came from ${VAR} expansion.
// Some errors quote only part of the value they reject (a regexp compile
// error shows the offending fragment), which apply cannot recognise, so for
// an expanded value the detail is withheld altogether.
func (r envRedaction) detail(value string, err error) error {
	if r.tainted(value) {
		return fmt.Errorf("invalid value from %s (details withheld: it would echo the expanded environment value)", r.fields[value])
	}
	return err
}

// apply rewrites msg so it no longer contains any expanded value: each
// expanded field value is replaced by its template, then any remaining
// occurrence of a substituted environment value by ${NAME}. Longer strings
// go first so a value that contains another is replaced whole. Both the raw
// and the %q-escaped spellings are replaced.
func (r envRedaction) apply(msg string) string {
	if len(r.fields) == 0 {
		return msg
	}
	msg = replaceLongestFirst(msg, r.fields, func(tmpl string) string { return tmpl })
	return replaceLongestFirst(msg, r.values, func(name string) string { return "${" + name + "}" })
}

func replaceLongestFirst(msg string, m map[string]string, repl func(string) string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		r := repl(m[k])
		msg = strings.ReplaceAll(msg, k, r)
		if q := strconv.Quote(k); q[1:len(q)-1] != k {
			msg = strings.ReplaceAll(msg, q[1:len(q)-1], r)
		}
	}
	return msg
}

// walk recurses into v, expanding any string it finds. path is a
// human-readable label (not necessarily valid Go/YAML syntax) used only for
// error messages.
func (e *envExpander) walk(v reflect.Value, path string) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return
		}
		e.walk(v.Elem(), path)

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			sf := t.Field(i)
			if sf.PkgPath != "" {
				continue // unexported: not settable, and not user-facing data
			}
			if sf.Tag.Get("env") == "-" {
				continue // opted out, e.g. a regexp replacement template
			}
			e.walk(v.Field(i), path+"."+fieldLabel(sf))
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			e.walk(v.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}

	case reflect.Map:
		e.walkMap(v, path)

	case reflect.String:
		e.expandString(v, path)
	}
}

// walkMap expands every value of a map.
func (e *envExpander) walkMap(v reflect.Value, path string) {
	if v.IsNil() {
		return
	}
	iter := v.MapRange()
	for iter.Next() {
		key := iter.Key()
		mv := iter.Value()
		elemPath := fmt.Sprintf("%s[%v]", path, key.Interface())
		if mv.Kind() == reflect.Ptr || mv.Kind() == reflect.Interface {
			// Pointer/interface map values reference shared memory, so
			// walking them in place mutates the real data.
			e.walk(mv, elemPath)
			continue
		}
		// Non-pointer map values aren't addressable straight out of the
		// map; expand a settable copy and write it back.
		nv := reflect.New(mv.Type()).Elem()
		nv.Set(mv)
		e.walk(nv, elemPath)
		v.SetMapIndex(key, nv)
	}
}

// expandString expands the ${VAR} references in one settable string.
func (e *envExpander) expandString(v reflect.Value, path string) {
	if !v.CanSet() {
		return
	}
	orig := v.String()
	if !strings.Contains(orig, "${") {
		return
	}
	if snippet, ok := malformedRef(orig); ok {
		e.malformed = append(e.malformed, fmt.Sprintf("%q in %s", snippet, path))
		return
	}
	expanded := envRef.ReplaceAllStringFunc(orig, func(m string) string {
		name := envRef.FindStringSubmatch(m)[1]
		val, ok := os.LookupEnv(name)
		if !ok {
			if !e.seenMissing[name] {
				e.seenMissing[name] = true
				e.missing = append(e.missing, name)
			}
			return m
		}
		e.record(val, name)
		return val
	})
	if expanded == orig {
		return
	}
	if e.redact.fields == nil {
		e.redact.fields = map[string]string{}
	}
	e.redact.fields[expanded] = orig
	v.SetString(expanded)
}

func (e *envExpander) record(val, name string) {
	if e.redact.values == nil {
		e.redact.values = map[string]string{}
	}
	e.redact.values[val] = name
}

// fieldLabel returns the yaml tag name for a struct field, for readable
// error paths, falling back to the Go field name when there is no tag.
func fieldLabel(sf reflect.StructField) string {
	tag := sf.Tag.Get("yaml")
	if i := strings.IndexByte(tag, ','); i >= 0 {
		tag = tag[:i]
	}
	if tag == "" || tag == "-" {
		return sf.Name
	}
	return tag
}

// malformedRef reports whether s contains a "${...}" span that does not
// match the strict envRef syntax (e.g. bash-style ${VAR:-default}). Only
// text that envRef fails to recognize at all is flagged — a reference to an
// unset-but-well-formed variable is reported separately as "missing", not
// "malformed".
func malformedRef(s string) (string, bool) {
	stripped := envRef.ReplaceAllString(s, "")
	stripped = numericGroupRef.ReplaceAllString(stripped, "")
	if !strings.Contains(stripped, "${") {
		return "", false
	}
	rest := stripped[strings.Index(stripped, "${"):]
	if end := strings.IndexByte(rest, '}'); end >= 0 {
		rest = rest[:end+1]
	} else if len(rest) > 40 {
		rest = rest[:40] + "..."
	}
	return rest, true
}
