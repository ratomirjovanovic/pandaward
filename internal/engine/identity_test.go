package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

const sqlLine = `  return db.query("SELECT * FROM users WHERE id=" + id);`

func sqlFile(lines ...string) string {
	s := "const db = require(\"db\");\n"
	for _, l := range lines {
		s += l + "\n"
	}
	return s
}

func findingsByRule(t *testing.T, e *Engine, rule string) []model.Finding {
	t.Helper()
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	var out []model.Finding
	for _, f := range fs {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

// Fixing the first of two identical hits must remediate the finding on the
// fixed line, not the one that is still there.
func TestFixOneOfIdenticalHits(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/a.js", sqlFile("function a(id) {", sqlLine, "}", "function b(id) {", sqlLine, "}"))
	e, _ := scan(t, root)
	before := findingsByRule(t, e, "code.sql-concat")
	e.Close()
	if len(before) != 2 {
		t.Fatalf("want 2 sql-concat findings, got %d", len(before))
	}
	lineOf := map[string]int{}
	for _, f := range before {
		lineOf[f.ID] = f.StartLine
	}

	testfixture.Write(t, root, "src/a.js", sqlFile("function a(id) {", `  return db.query("SELECT * FROM users WHERE id=?", [id]);`, "}", "function b(id) {", sqlLine, "}"))
	e, res := scan(t, root)
	defer e.Close()
	if res.Remediated != 1 || res.New != 0 {
		t.Fatalf("want 1 remediated and 0 new, got %d and %d", res.Remediated, res.New)
	}
	for _, f := range findingsByRule(t, e, "code.sql-concat") {
		switch lineOf[f.ID] {
		case 3:
			if f.Status != model.FindingRemediated {
				t.Errorf("%s on the fixed line 3 is %s, want REMEDIATED", f.ID, f.Status)
			}
		case 6:
			if f.Status != model.FindingOpen || f.StartLine != 6 {
				t.Errorf("%s on the unfixed line 6 is %s at line %d, want OPEN at 6", f.ID, f.Status, f.StartLine)
			}
		}
	}
}

// Renaming a file keeps its findings, their IDs and triage, and is neither
// a fix nor new findings.
func TestMovedFileKeepsFindings(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/a.js", sqlFile("function a(id) {", sqlLine, "}"))
	e, _ := scan(t, root)
	before := findingsByRule(t, e, "code.sql-concat")
	if len(before) != 1 {
		t.Fatalf("want 1 finding, got %d", len(before))
	}
	if _, err := e.Triage(before[0].ID, "accept-risk", "tester", "tracked in TICKET-1", time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	first, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()

	if err := os.MkdirAll(filepath.Join(root, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "src", "a.js"), filepath.Join(root, "lib", "a.js")); err != nil {
		t.Fatal(err)
	}
	e, res := scan(t, root)
	defer e.Close()
	if res.Moved != 1 || res.Remediated != 0 || res.New != 0 {
		t.Fatalf("want moved 1, remediated 0, new 0, got %d, %d, %d", res.Moved, res.Remediated, res.New)
	}
	after := findingsByRule(t, e, "code.sql-concat")
	if len(after) != 1 || after[0].ID != before[0].ID || after[0].File != "lib/a.js" || after[0].Status != model.FindingRiskAccepted {
		t.Fatalf("finding did not move with its file and triage: %+v", after)
	}
	d, err := e.Diff(first.ID, res.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Moved) != 1 || len(d.New)+len(d.Remediated) != 0 {
		t.Fatalf("diff: moved %d, new %d, remediated %d", len(d.Moved), len(d.New), len(d.Remediated))
	}
}

// A fix in one file plus the same pattern added to another file that still
// exists is a fix and a new finding, not a move.
func TestFixPlusCopyIsNotAMove(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/a.js", sqlFile("function a(id) {", sqlLine, "}"))
	e, _ := scan(t, root)
	e.Close()
	testfixture.Write(t, root, "src/a.js", sqlFile("function a(id) {", `  return db.query("SELECT * FROM users WHERE id=?", [id]);`, "}"))
	testfixture.Write(t, root, "src/b.js", sqlFile("function b(id) {", sqlLine, "}"))
	e, res := scan(t, root)
	defer e.Close()
	if res.Moved != 0 || res.Remediated != 1 || res.New != 1 {
		t.Fatalf("want moved 0, remediated 1, new 1, got %d, %d, %d", res.Moved, res.Remediated, res.New)
	}
}

func TestAlignLines(t *testing.T) {
	for _, c := range []struct {
		name string
		a, b []int
		want []int
	}{
		{"shifted together", []int{5, 8}, []int{3, 6}, []int{0, 1}},
		{"first fixed", []int{6}, []int{3, 6}, []int{1}},
		{"second fixed", []int{3}, []int{3, 6}, []int{0}},
		{"first fixed, rest shifted up", []int{5}, []int{3, 6}, []int{1}},
		{"one added below", []int{3, 6, 9}, []int{3, 6}, []int{0, 1, -1}},
		{"one added above", []int{1, 4, 7}, []int{3, 6}, []int{-1, 0, 1}},
		{"empty", nil, []int{3}, []int{}},
	} {
		got := alignLines(c.a, c.b)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}

// Lines inserted above identical hits shift them together; each finding
// must stay on its own hit.
func TestShiftKeepsIdentity(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/a.js", sqlFile("function a(id) {", sqlLine, "}", "function b(id) {", sqlLine, "}"))
	e, _ := scan(t, root)
	lineOf := map[string]int{}
	for _, f := range findingsByRule(t, e, "code.sql-concat") {
		lineOf[f.ID] = f.StartLine
	}
	e.Close()
	testfixture.Write(t, root, "src/a.js", "// header\n// more\n"+sqlFile("function a(id) {", sqlLine, "}", "function b(id) {", sqlLine, "}"))
	e, res := scan(t, root)
	defer e.Close()
	if res.New != 0 || res.Remediated != 0 {
		t.Fatalf("want no new or remediated findings, got %d and %d", res.New, res.Remediated)
	}
	for _, f := range findingsByRule(t, e, "code.sql-concat") {
		if f.StartLine != lineOf[f.ID]+2 {
			t.Errorf("%s was at line %d, now %d; want %d", f.ID, lineOf[f.ID], f.StartLine, lineOf[f.ID]+2)
		}
	}
}

// A renamed file with two identical hits keeps both findings, each on its
// own hit.
func TestMovedFileWithIdenticalHits(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/a.js", sqlFile("function a(id) {", sqlLine, "}", "function b(id) {", sqlLine, "}"))
	e, _ := scan(t, root)
	lineOf := map[string]int{}
	for _, f := range findingsByRule(t, e, "code.sql-concat") {
		lineOf[f.ID] = f.StartLine
	}
	e.Close()
	if err := os.Rename(filepath.Join(root, "src", "a.js"), filepath.Join(root, "src", "b.js")); err != nil {
		t.Fatal(err)
	}
	e, res := scan(t, root)
	defer e.Close()
	if res.Moved != 2 || res.New != 0 || res.Remediated != 0 {
		t.Fatalf("want moved 2, new 0, remediated 0, got %d, %d, %d", res.Moved, res.New, res.Remediated)
	}
	for _, f := range findingsByRule(t, e, "code.sql-concat") {
		if f.File != "src/b.js" || f.StartLine != lineOf[f.ID] {
			t.Errorf("%s: %s:%d, want src/b.js:%d", f.ID, f.File, f.StartLine, lineOf[f.ID])
		}
	}
}

// Without a snippet a move is accepted only when the new file has exactly
// the content the old file had when the finding was last observed.
func TestSnippetlessMoveNeedsSameContent(t *testing.T) {
	s := model.Signal{RuleID: "semgrep.rule", File: "lib/a.js", StartLine: 3, Collector: "semgrep"}
	old := model.Finding{ID: "PW-0001", RuleID: "semgrep.rule", File: "src/a.js", StartLine: 3, Collector: "semgrep", Status: model.FindingOpen,
		AssessmentID: "asmt_1", Fingerprint: fingerprint("semgrep.rule|src/a.js||", 1)}
	for _, same := range []bool{true, false} {
		a := assignFingerprints([]model.Signal{s}, []model.Finding{old}, fileView{
			exists:      func(string) bool { return false },
			sameContent: func(asmt, o, n string) bool { return same && asmt == "asmt_1" && o == "src/a.js" && n == "lib/a.js" },
		})
		if _, moved := a.Moved[0]; moved != same {
			t.Errorf("same content %v: moved %v", same, moved)
		}
	}
}
