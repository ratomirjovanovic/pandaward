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
	// Two measurements of main on the same day: the later run is latest,
	// whatever the directory names.
	write("z-morning", "meta.json", `{"label":"main aaaaaaa","date":"2026-12-09","time":"2026-12-09T08:00:00Z","url":"https://example.invalid/a"}`)
	write("z-morning", "cve.json", cve)
	write("a-evening", "meta.json", `{"label":"main bbbbbbb","date":"2026-12-09","time":"2026-12-09T20:00:00Z","url":"https://example.invalid/b"}`)
	write("a-evening", "cve.json", cve)
	snaps, err = Load([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if snaps[0].Label != "main bbbbbbb" || snaps[1].Label != "main aaaaaaa" {
		t.Fatalf("same-day order: %s, %s", snaps[0].Label, snaps[1].Label)
	}

	// The same commit from a committed snapshot and from the site build's
	// run of main shows once.
	write("run-copy", "meta.json", `{"label":"main bbbbbbb","date":"2026-12-09","time":"2026-12-09T20:00:00Z","url":"https://example.invalid/b"}`)
	write("run-copy", "cve.json", cve)
	snaps, err = Load([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if snaps[0].Label != "main bbbbbbb" || snaps[1].Label != "main aaaaaaa" {
		t.Fatalf("duplicate source kept: %s, %s", snaps[0].Label, snaps[1].Label)
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

// The combined PandaWard row comes first in the CVE table and in the
// history; an older snapshot without it shows "-" in that column.
func TestRenderCombinedCVE(t *testing.T) {
	cve, err := parseCVE([]byte(`{"benchmark_commit":"91c59fd5","engines":[` +
		`{"engine":"pandaward","version":"built-in + semgrep","scored":219,"detected":88,"fix_recognized":45,"detection_rate":0.4},` +
		`{"engine":"builtin","version":"dev","scored":219,"detected":45,"fix_recognized":28,"detection_rate":0.2}]}`))
	if err != nil {
		t.Fatal(err)
	}
	old, err := parseCVE([]byte(`{"engines":[{"engine":"builtin","scored":219,"detected":23}]}`))
	if err != nil {
		t.Fatal(err)
	}
	snaps := []Snapshot{
		{Meta: Meta{Label: "main", Date: "2026-11-10", URL: "https://example.invalid/new"}, CVE: cve},
		{Meta: Meta{Label: "main", Date: "2026-11-09", URL: "https://example.invalid/old"}, CVE: old},
	}
	var b bytes.Buffer
	if err := Render(&b, snaps); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"PandaWard <small>built-in &#43; semgrep</small>", "<b>88</b> of 219", ">88/219<", ">-<", ">23/219<"} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Index(html, "PandaWard <small>") > strings.Index(html, "Built-in heuristics") {
		t.Error("PandaWard row is not first")
	}
}

func TestOWASPTotals(t *testing.T) {
	s, err := parseOWASP([]byte(`{"engines":[`+
		`{"engine":"builtin","average_score_covered":0.1,"totals":{"precision":0.5,"recall":0.25,"f1":0.333,"fp_per_kloc":1.5,"seconds":3.2},"categories":[{"category":"sqli","covered":true,"score":0.1}]},`+
		`{"engine":"semgrep","average_score_covered":0.2,"categories":[{"category":"sqli","covered":true,"score":0.2}]}]}`), "java", "Java")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Engines[0].HasTotals || s.Engines[0].Precision != 0.5 || s.Engines[0].Seconds != 3.2 {
		t.Errorf("builtin %+v", s.Engines[0])
	}
	if s.Engines[1].HasTotals {
		t.Errorf("semgrep has no totals: %+v", s.Engines[1])
	}
}
