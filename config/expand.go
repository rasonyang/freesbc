package config

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
)

// envRef matches ${VAR_NAME} — the only supported reference syntax. Anything
// else that merely looks like a "${" reference (e.g. bash-style
// ${VAR:-default}) is rejected rather than silently passed through as a
// literal.
var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv walks a freshly unmarshalled Config and expands ${VAR}
// references in every exported string field — including slices, maps, and
// nested structs/pointers — so fields added in later milestones are covered
// automatically without touching this file again.
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
			e.walk(v.Field(i), path+"."+fieldLabel(sf))
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			e.walk(v.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}

	case reflect.Map:
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

	case reflect.String:
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
		expanded := envRef.ReplaceAllFunc([]byte(orig), func(m []byte) []byte {
			name := string(envRef.FindSubmatch(m)[1])
			val, ok := os.LookupEnv(name)
			if !ok {
				if !e.seenMissing[name] {
					e.seenMissing[name] = true
					e.missing = append(e.missing, name)
				}
				return m
			}
			return []byte(val)
		})
		v.SetString(string(expanded))
	}
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
