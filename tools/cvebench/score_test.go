package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/tools/internal/engines"
)

func cve(t *testing.T) CVE {
	t.Helper()
	var c CVE
	c.ID, c.State, c.Repository = "CVE-2020-0001", "PUBLISHED", "https://example.invalid/r.git"
	c.PrePatch.Commit, c.PostPatch.Commit = strings.Repeat("a", 40), strings.Repeat("b", 40)
	var w Weakness
	w.Location.File, w.Location.Line = "lib/render.js", 42
	c.PrePatch.Weaknesses = []Weakness{w}
	c.CWEs = []string{"CWE-079", "CWE-116"}
	return c
}

func TestCWENumber(t *testing.T) {
	for in, want := range map[string]int{"CWE-079": 79, "CWE-79: Improper": 79, "79": 79, "cwe-22": 22, "": 0, "x": 0} {
		if got := CWENumber(in); got != want {
			t.Errorf("CWENumber(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestScore(t *testing.T) {
	c := cve(t)
	hit := engines.Finding{Rule: "semgrep.pandaward-js-html-sink", CWE: "CWE-79: XSS", File: "lib/render.js", Line: 42, EndLine: 42}
	span := engines.Finding{Rule: "code.html-sink", File: "./lib/render.js", Line: 40, EndLine: 44}
	near := engines.Finding{Rule: "code.other", File: "lib/render.js", Line: 43, EndLine: 43}
	elsewhere := engines.Finding{Rule: "semgrep.pandaward-js-html-sink", File: "lib/other.js", Line: 42, EndLine: 42}

	// Detected on the exact line and inside a multi-line span; a finding on a
	// neighbouring line or in another file does not count.
	o := Score(c, "semgrep", []engines.Finding{hit, span, near, elsewhere}, []engines.Finding{span, near})
	if !o.Detected || !o.CWEMatch || strings.Join(o.Rules, ",") != "code.html-sink,semgrep.pandaward-js-html-sink" {
		t.Fatalf("outcome %+v", o)
	}
	if o.FindingsInVulnerableFiles != 3 || o.CWE != 79 {
		t.Fatalf("outcome %+v", o)
	}
	// The html-sink rule still fires after the fix, but the semgrep rule no
	// longer does: the fix is recognized.
	if !o.FixRecognized {
		t.Fatal("fix not recognized although a detecting rule dropped a finding")
	}

	// Every detecting rule reports as much after the fix: still flagged.
	o = Score(c, "builtin", []engines.Finding{span}, []engines.Finding{span})
	if !o.Detected || o.FixRecognized || o.CWEMatch {
		t.Fatalf("still flagged case: %+v", o)
	}

	// Nothing on the line: missed, and fix recognition is not judged.
	o = Score(c, "builtin", []engines.Finding{near, elsewhere}, nil)
	if o.Detected || o.FixRecognized || len(o.Rules) != 0 {
		t.Fatalf("missed case: %+v", o)
	}
}

func TestSummary(t *testing.T) {
	var s Summary
	s.Add(Outcome{CVE: "a", CWE: 79, Detected: true, FixRecognized: true, CWEMatch: true, Rules: []string{"r1"}})
	s.Add(Outcome{CVE: "b", CWE: 79, Detected: true, Rules: []string{"r1"}})
	s.Add(Outcome{CVE: "c", CWE: 22})
	s.Finish()
	if s.Scored != 3 || s.Detected != 2 || s.FixRecognized != 1 || s.StillFlagged != 1 || s.CWEMatch != 1 || s.Rules["r1"] != 2 {
		t.Fatalf("summary %+v", s)
	}
	if s.DetectionRate < 0.66 || s.DetectionRate > 0.67 || s.FixRate != 0.5 {
		t.Fatalf("rates %v %v", s.DetectionRate, s.FixRate)
	}
	if len(s.ByCWE) != 2 || s.ByCWE[0].CWE != 79 || s.ByCWE[0].Detected != 2 {
		t.Fatalf("by CWE %+v", s.ByCWE)
	}
}

func TestLoadCVEs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "CVEs"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := `{"CVE":"CVE-2020-2","state":"PUBLISHED","repository":"https://x/y.git","prePatch":{"commit":"` + strings.Repeat("a", 40) + `","weaknesses":[{"location":{"file":"a.js","line":1},"explanation":"x"}]},"postPatch":{"commit":"` + strings.Repeat("b", 40) + `"},"CWEs":["CWE-022"]}`
	rejected := `{"CVE":"CVE-2020-1","state":"REJECTED","repository":"https://x/y.git","prePatch":{"commit":"` + strings.Repeat("a", 40) + `","weaknesses":[]},"postPatch":{"commit":"main"},"CWEs":[]}`
	for name, body := range map[string]string{"CVE-2020-2.json": good, "CVE-2020-1.json": rejected} {
		if err := os.WriteFile(filepath.Join(dir, "CVEs", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cves, skipped, err := LoadCVEs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 || cves[0].ID != "CVE-2020-2" || skipped != 1 {
		t.Fatalf("got %d CVEs, %d skipped", len(cves), skipped)
	}
	if _, _, err := LoadCVEs(t.TempDir()); err == nil {
		t.Fatal("an empty directory must be an error")
	}
}

func TestRunScriptUsesPinnedCommit(t *testing.T) {
	b, err := os.ReadFile("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "commit="+PinnedCommit+"\n") {
		t.Fatal("run.sh and PinnedCommit disagree")
	}
}

// An interrupted run's journal is read back; a torn last line is ignored.
func TestJournal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "results.jsonl")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := appendJournal(f, record{CVE: "CVE-1", Outcomes: []Outcome{{CVE: "CVE-1", Engine: "builtin", Detected: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := appendJournal(f, record{CVE: "CVE-2", Unavailable: true, Reason: "gone"}); err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"cve":"CVE-3","outco`)
	f.Close()
	got, err := readJournal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["CVE-1"].Outcomes[0].Detected || !got["CVE-2"].Unavailable {
		t.Fatalf("journal %+v", got)
	}
	if got, err := readJournal(filepath.Join(t.TempDir(), "none.jsonl")); err != nil || len(got) != 0 {
		t.Fatalf("missing journal: %v %v", got, err)
	}
	if safeName("0.2.15-dev+abc/x") != "0.2.15-dev_abc_x" {
		t.Fatal(safeName("0.2.15-dev+abc/x"))
	}
}
