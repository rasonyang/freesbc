package sip

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/freesbc/freesbc"

// audit: P2-SIP-009
// Every exported function, variable and constant of this package is used
// by another package of the module (tests excluded). A helper only this
// package calls is kept unexported, so the package's surface is exactly
// what the planes share. Types are not checked: a type such as Editable is
// part of the surface through the signatures that use it.
func TestExportsUsedOutsidePackage(t *testing.T) {
	fset := token.NewFileSet()
	exported := map[string]bool{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.IsExported() {
					exported[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if s, ok := s.(*ast.ValueSpec); ok {
						for _, n := range s.Names {
							if n.IsExported() {
								exported[n.Name] = true
							}
						}
					}
				}
			}
		}
	}

	used := map[string]bool{}
	self := modulePath + "/internal/sip"
	err = filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") && path != "../.." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		alias := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == self {
				alias = "sip"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
			}
		}
		if alias == "" {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == alias {
					used[sel.Sel.Name] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var unused []string
	for name := range exported {
		if !used[name] {
			unused = append(unused, name)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		t.Errorf("exported but used only inside internal/sip (unexport them): %v", unused)
	}
}
