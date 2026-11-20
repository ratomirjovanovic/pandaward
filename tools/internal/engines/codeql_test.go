package engines

import (
	"context"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

func TestParseSARIF(t *testing.T) {
	in := `{"runs":[{"tool":{"driver":{"rules":[{"id":"py/sql-injection","properties":{"tags":["security","external/cwe/cwe-089"]}}]},"extensions":[{"rules":[{"id":"py/path-injection","properties":{"tags":["external/cwe/cwe-022","external/cwe/cwe-023"]}}]}]},"results":[` +
		`{"ruleId":"py/sql-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"testcode/BenchmarkTest00001.py"},"region":{"startLine":12,"endLine":14}}}]},` +
		`{"ruleId":"py/path-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"./a/b.py"},"region":{"startLine":3}}}]},` +
		`{"ruleId":"py/other","locations":[]}]}]}`
	fs, err := parseSARIF([]byte(in))
	if err != nil || len(fs) != 2 {
		t.Fatalf("%v %+v", err, fs)
	}
	if fs[0].Rule != "codeql.py/sql-injection" || fs[0].CWE != "CWE-89" || fs[0].File != "testcode/BenchmarkTest00001.py" || fs[0].Line != 12 || fs[0].EndLine != 14 {
		t.Errorf("first %+v", fs[0])
	}
	if fs[1].CWE != "CWE-22" || fs[1].File != "a/b.py" || fs[1].EndLine != 3 {
		t.Errorf("second %+v", fs[1])
	}
	if _, err := parseSARIF([]byte("nope")); err == nil {
		t.Error("not JSON must be an error")
	}
}

func TestCodeQLNotRun(t *testing.T) {
	inv := &inventory.Inventory{Languages: map[string]int{"java": 3}}
	r, err := codeql(context.Background(), inv)
	if err != nil || r.NotRun == "" {
		t.Fatalf("java tree: %v %+v", err, r)
	}
	t.Setenv(CodeQLHome, "")
	inv.Languages["python"] = 1
	r, err = codeql(context.Background(), inv)
	if err != nil || r.NotRun == "" {
		t.Fatalf("no home: %v %+v", err, r)
	}
}
