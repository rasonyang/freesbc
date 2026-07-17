package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("old: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new: 2\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new: 2\n" {
		t.Fatalf("content = %q, want new", got)
	}
	// no leftover temp files in the dir
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected only cfg.yaml, got %d entries (temp leak?)", len(entries))
	}
}

func TestWriteFileAtomicBadDirLeavesOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(path, []byte("keep\n"), 0o600)
	// point at a non-existent directory → CreateTemp fails → original intact
	bad := filepath.Join(dir, "nope", "cfg.yaml")
	if err := writeFileAtomic(bad, []byte("x"), 0o600); err == nil {
		t.Fatal("expected error writing into a missing dir")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "keep\n" {
		t.Fatalf("original mutated: %q", got)
	}
}

func TestEtagOf(t *testing.T) {
	a := etagOf([]byte("hello"))
	b := etagOf([]byte("hello"))
	c := etagOf([]byte("world"))
	if a != b {
		t.Error("etag not deterministic")
	}
	if a == c {
		t.Error("different content → same etag")
	}
	if !strings.HasPrefix(a, `"`) || !strings.HasSuffix(a, `"`) {
		t.Errorf("etag must be quoted: %s", a)
	}
}
