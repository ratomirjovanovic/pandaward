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
		if got := CategoryOf(c.rule, c.cwe); got != c.want {
			t.Errorf("CategoryOf(%q, %q) = %q, want %q", c.rule, c.cwe, got, c.want)
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
		if got := TestCaseOf(in); got != want {
			t.Errorf("TestCaseOf(%q) = %q, want %q", in, got, want)
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
	s := Compute(expected, findings, covered)
	if s.TestCases != 7 || s.Findings != 6 || s.FindingsInTests != 4 || s.OffCategory != 1 || s.FindingsElsewhere != 1 || s.UnknownTestCases != 1 {
		t.Fatalf("unexpected totals: %+v", s)
	}
	if len(s.Categories) != len(Categories) {
		t.Fatalf("got %d categories, want %d", len(s.Categories), len(Categories))
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
	perfect := Compute(expected, []Finding{
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
	for id := range ruleCategory {
		if !known[id] {
			t.Errorf("ruleCategory names unknown rule %s", id)
		}
	}
}

func TestBenchmarkPathsAreNotTestPaths(t *testing.T) {
	if adapters.IsTestPath("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java") {
		t.Fatal("Benchmark test cases would be skipped by the code heuristics")
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
