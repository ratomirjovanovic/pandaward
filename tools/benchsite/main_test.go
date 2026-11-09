package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The committed snapshot renders, with every suite, the CVE table and a
// history row that links to its source.
func TestRenderCommittedSnapshot(t *testing.T) {
	snaps, err := Load([]string{filepath.Join("..", "..", "site", "benchmarks", "snapshots")})
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) == 0 {
		t.Fatal("no committed snapshot")
	}
	var b bytes.Buffer
	if err := Render(&b, snaps); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"OWASP Benchmark for Java", "OWASP Benchmark for Python", "OpenSSF CVE Benchmark", "History", snaps[0].URL, "tools/cvebench/run.sh"} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(html, "<no value>") || strings.Contains(html, "dev</small>") {
		t.Error("page shows an unset value or a source build version")
	}
}

// Snapshots are ordered newest first; one without results is skipped, and
// meta.json must name label, date and url.
func TestLoad(t *testing.T) {
	root := t.TempDir()
	write := func(dir, name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cve := `{"benchmark_commit":"91c59fd5","unavailable":["x"],"engines":[{"engine":"builtin","scored":219,"detected":23,"fix_recognized":10,"detection_rate":0.105}]}`
	write("old", "meta.json", `{"label":"0.2.15","date":"2026-11-20","url":"https://example.invalid/r/0.2.15"}`)
	write("old", "cve.json", cve)
	write("new", "meta.json", `{"label":"0.2.16","date":"2026-12-01","url":"https://example.invalid/r/0.2.16","assets":{"cve.json":"https://example.invalid/cve.json"}}`)
	write("new", "cve.json", cve)
	write("empty", "meta.json", `{"label":"x","date":"2026-12-05","url":"https://example.invalid"}`)
	snaps, err := Load([]string{root, filepath.Join(root, "missing")})
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 || snaps[0].Label != "0.2.16" || snaps[1].Label != "0.2.15" {
		t.Fatalf("snapshots %+v", snaps)
	}
	if snaps[0].CVE.Asset != "https://example.invalid/cve.json" || snaps[0].CVE.Unavailable != 1 || snaps[0].CVE.Scored != 219 {
		t.Fatalf("cve %+v", snaps[0].CVE)
	}
	write("bad", "meta.json", `{"label":"x"}`)
	if _, err := Load([]string{root}); err == nil {
		t.Fatal("meta.json without date and url was accepted")
	}
}

func TestEngineVersion(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"opengrep", "opengrep 1.33.1", "1.33.1"},
		{"semgrep", "1.182.1", "1.182.1"},
		{"builtin", "dev", ""},
		{"builtin", "0.2.15-0.20261109082449-a3111b0cad93+dirty", ""},
		{"builtin", "0.2.15", "0.2.15"},
	} {
		if got := EngineVersion(c.name, c.in); got != c.want {
			t.Errorf("EngineVersion(%q, %q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
