package main

import (
	"strings"
	"testing"
)

func f(v float64) *float64 { return &v }
func n(v int) *int         { return &v }

func TestCompare(t *testing.T) {
	base := Baseline{Scores: map[string]Scores{
		"owasp/python/opengrep": {AverageCovered: f(0.059), Categories: map[string]float64{"pathtraver": 0.092, "cmdi": -0.462}},
		"owasp/python/semgrep":  {AverageCovered: f(0.039)},
		"owasp/java/builtin":    {AverageCovered: f(0)},
		"cve/builtin":           {Detected: n(23), FixRecognized: n(10)},
	}}

	// Equal or better passes; a new entry is listed, not failed; Java and
	// CVE entries are not required when only Python was measured.
	got := map[string]Scores{
		"owasp/python/opengrep": {AverageCovered: f(0.0592), Categories: map[string]float64{"pathtraver": 0.10, "cmdi": -0.462, "xss": 0.1}},
		"owasp/python/semgrep":  {AverageCovered: f(0.039)},
		"owasp/python/builtin":  {AverageCovered: f(0.02)},
	}
	lines, failed := Compare(base, got)
	if failed != 0 {
		t.Fatalf("failed %d:\n%s", failed, strings.Join(lines, "\n"))
	}
	if !strings.Contains(strings.Join(lines, "\n"), "NEW   owasp/python/builtin") {
		t.Fatalf("new entry not listed:\n%s", strings.Join(lines, "\n"))
	}

	// A lower average, a lower category, a lost category and a missing
	// engine of a measured suite all fail.
	got = map[string]Scores{
		"owasp/python/opengrep": {AverageCovered: f(0.05), Categories: map[string]float64{"pathtraver": 0.09}},
		"cve/builtin":           {Detected: n(22), FixRecognized: n(10)},
	}
	lines, failed = Compare(base, got)
	out := strings.Join(lines, "\n")
	for _, want := range []string{"FAIL  owasp/python/opengrep average", "FAIL  owasp/python/opengrep pathtraver", "FAIL  owasp/python/opengrep cmdi is no longer covered", "FAIL  owasp/python/semgrep was not measured", "FAIL  cve/builtin detected"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if failed != 5 {
		t.Fatalf("failed = %d, want 5:\n%s", failed, out)
	}
	if strings.Contains(out, "owasp/java/builtin") {
		t.Fatalf("Java was not measured and must not fail:\n%s", out)
	}
}
