package engines

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func TestParseDefaultJSON(t *testing.T) {
	out := `{"results":[
	 {"check_id":"python.lang.security.audit.subprocess-shell-true","path":"./a/b.py","start":{"line":4},"end":{"line":6},"extra":{"metadata":{"cwe":["CWE-78: Improper Neutralization of Special Elements used in an OS Command"]}}},
	 {"check_id":"java.lang.security.audit.crypto.weak-hash","path":"x/Y.java","start":{"line":9},"end":{"line":3},"extra":{"metadata":{"cwe":"CWE-328: Use of Weak Hash"}}},
	 {"check_id":"generic.secrets.token","path":"c.js","start":{"line":1},"end":{"line":1},"extra":{"metadata":{}}}
	],"errors":[]}`
	got, err := parseDefaultJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	want := []Finding{
		{Rule: "python.lang.security.audit.subprocess-shell-true", CWE: "CWE-78: Improper Neutralization of Special Elements used in an OS Command", File: "a/b.py", Line: 4, EndLine: 6},
		{Rule: "java.lang.security.audit.crypto.weak-hash", CWE: "CWE-328: Use of Weak Hash", File: "x/Y.java", Line: 9, EndLine: 9},
		{Rule: "generic.secrets.token", File: "c.js", Line: 1, EndLine: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if _, err := parseDefaultJSON("not json"); err == nil {
		t.Fatal("garbage must be an error")
	}
}

// Without the tool or the rules the engine is not run, which is not a score of zero.
func TestDefaultEnginesAreNotRunWithoutTheirInputs(t *testing.T) {
	t.Setenv(OpengrepRules, "")
	inv, err := Walk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := Measure(context.Background(), inv, "opengrep-default")
	if err != nil || r.NotRun == "" || len(r.Findings) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	t.Setenv("PATH", t.TempDir())
	if r, err := Measure(context.Background(), inv, "semgrep-default"); err != nil || r.NotRun == "" {
		t.Fatalf("a missing tool is NotRun: %+v %v", r, err)
	}
	_ = os.Getenv
}

func TestDefaultEnginesAreListed(t *testing.T) {
	got, err := Parse("semgrep-default,opengrep-default")
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
}

// A scan that did not happen is not "no findings".
func TestFatalExit(t *testing.T) {
	for code, want := range map[int]bool{0: false, 1: false, 2: true, 7: true, 3: true, 124: true} {
		if got := fatalExit(code); got != want {
			t.Errorf("fatalExit(%d) = %v, want %v", code, got, want)
		}
	}
}
