package main

import (
	"math"
	"os"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
)

const sampleCSV = `# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
BenchmarkTest00001,sqli,true,89
BenchmarkTest00002,sqli,true,89
BenchmarkTest00003,sqli,false,89
BenchmarkTest00004,sqli,false,89
BenchmarkTest00005,hash,true,328
BenchmarkTest00006,hash,false,328
BenchmarkTest00007,ldapi,true,90
`

func TestParseExpected(t *testing.T) {
	got, err := ParseExpected(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 {
		t.Fatalf("got %d cases, want 7", len(got))
	}
	if want := (Expected{"BenchmarkTest00005", "hash", true, 328}); got[4] != want {
		t.Fatalf("got %+v, want %+v", got[4], want)
	}
	if _, err := ParseExpected(strings.NewReader("BenchmarkTest00001,sqli,maybe,89\n")); err == nil {
		t.Fatal("want an error for a bad label")
	}
}

func TestCategoryOf(t *testing.T) {
	for _, c := range []struct{ rule, cwe, want string }{
		{"code.sql-concat", "CWE-89", "sqli"},
		{"code.weak-hash-password", "CWE-327", "hash"}, // rule mapping wins over CWE
		{"some.future-rule", "CWE-22", "pathtraver"},
		{"some.future-rule", "CWE-338", "weakrand"},
		{"code.java-deserialize", "CWE-502", ""},
		{"x", "", ""},
	} {
		if got := Java.CategoryOf(c.rule, c.cwe); got != c.want {
			t.Errorf("Java.CategoryOf(%q, %q) = %q, want %q", c.rule, c.cwe, got, c.want)
		}
	}
}

func TestTestCaseOf(t *testing.T) {
	for in, want := range map[string]string{
		"src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00042.java": "BenchmarkTest00042",
		`src\main\java\BenchmarkTest00042.java`:                              "BenchmarkTest00042",
		"src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00042.xml":  "",
		"src/main/java/org/owasp/benchmark/helpers/Utils.java":               "",
	} {
		if got := Java.TestCaseOf(in); got != want {
			t.Errorf("Java.TestCaseOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompute(t *testing.T) {
	expected, err := ParseExpected(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	dir := "src/main/java/org/owasp/benchmark/testcode/"
	findings := []Finding{
		{Rule: "code.sql-concat", CWE: "CWE-89", File: dir + "BenchmarkTest00001.java"},
		{Rule: "code.sql-template", CWE: "CWE-89", File: dir + "BenchmarkTest00001.java"}, // second hit, same case
		{Rule: "code.sql-concat", CWE: "CWE-89", File: dir + "BenchmarkTest00003.java"},
		{Rule: "code.html-sink", CWE: "CWE-79", File: dir + "BenchmarkTest00002.java"}, // other category
		{Rule: "code.sql-concat", CWE: "CWE-89", File: "src/main/java/Helper.java"},
		{Rule: "code.sql-concat", CWE: "CWE-89", File: dir + "BenchmarkTest09999.java"},
	}
	covered := map[string][]string{"sqli": {"code.sql-concat"}, "hash": {"code.weak-hash-password"}}
	s := Java.Compute(expected, findings, covered)
	if s.TestCases != 7 || s.Findings != 6 || s.FindingsInTests != 4 || s.OffCategory != 1 || s.FindingsElsewhere != 1 || s.UnknownTestCases != 1 {
		t.Fatalf("unexpected totals: %+v", s)
	}
	if len(s.Categories) != len(Java.Categories) {
		t.Fatalf("got %d categories, want %d", len(s.Categories), len(Java.Categories))
	}
	by := map[string]CategoryResult{}
	for _, r := range s.Categories {
		by[r.Category] = r
	}
	sq := by["sqli"]
	if sq.TP != 1 || sq.FN != 1 || sq.FP != 1 || sq.TN != 1 || sq.TPR != 0.5 || sq.FPR != 0.5 || sq.Score != 0 || !sq.Covered {
		t.Fatalf("sqli: %+v", sq)
	}
	h := by["hash"]
	if h.TP != 0 || h.FN != 1 || h.TN != 1 || h.Score != 0 || !h.Covered {
		t.Fatalf("hash: %+v", h)
	}
	l := by["ldapi"]
	if l.Covered || l.Real != 1 || l.FN != 1 {
		t.Fatalf("ldapi should be not covered with one real case: %+v", l)
	}
	if by["xss"].Covered != true {
		t.Fatal("a mapped finding marks its category as covered")
	}
	if by["crypto"].Covered {
		t.Fatal("crypto has no rule and no finding")
	}
	if s.AverageCovered != 0 || s.AverageAll != 0 {
		t.Fatalf("averages: %v %v", s.AverageCovered, s.AverageAll)
	}

	// A perfect sqli result gives a score of 1.
	perfect := Java.Compute(expected, []Finding{
		{Rule: "code.sql-concat", File: dir + "BenchmarkTest00001.java"},
		{Rule: "code.sql-concat", File: dir + "BenchmarkTest00002.java"},
	}, covered)
	for _, r := range perfect.Categories {
		if r.Category == "sqli" && r.Score != 1 {
			t.Fatalf("perfect sqli: %+v", r)
		}
	}
	if math.Abs(perfect.AverageCovered-0.5) > 1e-9 || math.Abs(perfect.AverageAll-1.0/11) > 1e-9 {
		t.Fatalf("averages: %v %v", perfect.AverageCovered, perfect.AverageAll)
	}
}

// Every mapped rule must exist, so a rename cannot silently turn a category
// into "not covered".
func TestMappedRulesExist(t *testing.T) {
	known := map[string]bool{}
	for _, id := range adapters.RuleIDs() {
		known[id] = true
	}
	for _, st := range Suites {
		for id := range st.Rules {
			if !known[id] {
				t.Errorf("%s suite names unknown rule %s", st.Key, id)
			}
		}
	}
}

func TestBenchmarkPathsAreNotTestPaths(t *testing.T) {
	for _, st := range Suites {
		if p := st.TestCodeDir + "/BenchmarkTest00001" + st.Ext; adapters.IsTestPath(p) {
			t.Fatalf("%s: Benchmark test cases would be skipped by the code heuristics (%s)", st.Key, p)
		}
	}
}

func TestRunScriptUsesPinnedCommit(t *testing.T) {
	b, err := os.ReadFile("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range Suites {
		if !strings.Contains(string(b), "commit="+st.PinnedCommit+" url="+st.URL+"\n") {
			t.Errorf("run.sh and the %s suite's pinned commit or URL disagree", st.Key)
		}
	}
}

func TestCategoryOfCWEForms(t *testing.T) {
	for cwe, want := range map[string]string{"CWE-89": "sqli", "89": "sqli", "CWE-89: Improper Neutralization": "sqli", "cwe-22": "pathtraver", "CWE-918": "", "": "", "x89": ""} {
		if got := Java.CategoryOf("semgrep.x", cwe); got != want {
			t.Errorf("Java.CategoryOf(%q) = %q, want %q", cwe, got, want)
		}
	}
}

// The bundled Java rules cover the categories their CWE names; rules for
// other languages and CWEs outside the Benchmark are left out.
func TestSemgrepCoverage(t *testing.T) {
	got, err := Java.SemgrepCoverage()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"sqli", "cmdi", "pathtraver", "crypto"} {
		if len(got[c]) == 0 {
			t.Errorf("no bundled Java rule covers %s: %v", c, got)
		}
	}
	for c, rs := range got {
		for _, r := range rs {
			if !strings.HasPrefix(r, "semgrep.pandaward-java-") {
				t.Errorf("%s covered by %s, not a bundled Java rule", c, r)
			}
		}
	}
}

// Merged engines count a test case once, however many engines flag it.
func TestMergedEnginesCountOnce(t *testing.T) {
	expected := []Expected{{Name: "BenchmarkTest00001", Category: "sqli", Real: true, CWE: 89}, {Name: "BenchmarkTest00002", Category: "sqli", Real: false, CWE: 89}}
	f := "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"
	findings := []Finding{{Rule: "code.sql-concat", File: f}, {Rule: "semgrep.pandaward-java-sql-string", CWE: "CWE-89: Improper", File: f}}
	s := Java.Compute(expected, findings, map[string][]string{"sqli": {"code.sql-concat"}})
	for _, r := range s.Categories {
		if r.Category == "sqli" && (r.TP != 1 || r.FP != 0 || r.TN != 1 || r.Score != 1) {
			t.Fatalf("sqli = %+v", r)
		}
	}
}

// BenchmarkPython ships an HTML template per test case; only the .py file is
// the test case.
func TestPythonTestCaseOf(t *testing.T) {
	for in, want := range map[string]string{
		"testcode/BenchmarkTest00042.py":                      "BenchmarkTest00042",
		"templates/web/pathtraver-00/BenchmarkTest00042.html": "",
		"testcode/BenchmarkTest00042.java":                    "",
		"helpers/utils.py":                                    "",
	} {
		if got := Python.TestCaseOf(in); got != want {
			t.Errorf("Python.TestCaseOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// Python categories that Java lacks map by CWE, and Python rules map to
// their categories only in the Python suite.
func TestPythonCategories(t *testing.T) {
	for _, c := range []struct{ rule, cwe, want string }{
		{"code.py-eval", "", "codeinj"},
		{"code.py-deserialize", "", "deserialization"},
		{"semgrep.x", "CWE-601", "redirect"},
		{"semgrep.x", "CWE-611", "xxe"},
		{"semgrep.x", "CWE-95", "codeinj"},
	} {
		if got := Python.CategoryOf(c.rule, c.cwe); got != c.want {
			t.Errorf("Python.CategoryOf(%q, %q) = %q, want %q", c.rule, c.cwe, got, c.want)
		}
	}
	if got := Java.CoveredCategories([]string{"code.py-shell"}); len(got) != 0 {
		t.Errorf("a Python rule covers Java categories: %v", got)
	}
	if got := Python.CoveredCategories([]string{"code.java-shell"}); len(got) != 0 {
		t.Errorf("a Java rule covers Python categories: %v", got)
	}
	cov, err := Python.SemgrepCoverage()
	if err != nil {
		t.Fatal(err)
	}
	for c, rs := range cov {
		for _, r := range rs {
			if !strings.HasPrefix(r, "semgrep.pandaward-py") {
				t.Errorf("%s covered by %s, not a bundled Python rule", c, r)
			}
		}
	}
}
