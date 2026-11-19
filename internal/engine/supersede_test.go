package engine

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// A built-in SQL heuristic in a Java or JavaScript file is replaced by the
// bundled taint rule of that language (JavaScript since #352); a JavaScript
// shell heuristic and a Java signal of another rule stay.
func TestSupersededSignals(t *testing.T) {
	inv := &inventory.Inventory{Files: []*inventory.File{
		{Path: "src/Dao.java", Lang: "java"},
		{Path: "web/db.js", Lang: "javascript"},
	}}
	sigs := []model.Signal{
		{RuleID: "code.sql-concat", ControlID: "D-003", Collector: "builtin-code", File: "src/Dao.java"},
		{RuleID: "code.sql-concat", ControlID: "D-003", Collector: "builtin-code", File: "web/db.js"},
		{RuleID: "code.tls-verify-off", ControlID: "E-003", Collector: "builtin-code", File: "src/Dao.java"},
		{RuleID: "code.js-shell", ControlID: "D-002", Collector: "builtin-code", File: "web/db.js"},
		{RuleID: "semgrep.pandaward-java-sql-injection", ControlID: "D-003", Collector: "semgrep", File: "src/Dao.java"},
	}
	sigs = append(sigs, model.Signal{RuleID: "semgrep.pandaward-js-sql-injection", ControlID: "D-003", Collector: "semgrep", File: "web/db.js"})
	got := supersededSignals(sigs, inv)
	if len(got) != 2 || got[0] != "semgrep.pandaward-java-sql-injection" || got[1] != "semgrep.pandaward-js-sql-injection" {
		t.Fatalf("superseded = %v, want signals 0 and 1", got)
	}
	// A replacing rule that reports nothing near the signal does not decide
	// it: the heuristic finding stays.
	far := []model.Signal{
		{RuleID: "code.sql-concat", ControlID: "D-003", Collector: "builtin-code", File: "src/Dao.java", StartLine: 40},
		{RuleID: "semgrep.pandaward-java-sql-injection", ControlID: "D-003", Collector: "semgrep", File: "src/Dao.java", StartLine: 10},
	}
	if got := supersededSignals(far, inv); len(got) != 0 {
		t.Fatalf("a rule far from the signal must not replace it: %v", got)
	}
	near := []model.Signal{far[0], {RuleID: "semgrep.pandaward-java-sql-injection", ControlID: "D-003", Collector: "semgrep", File: "src/Dao.java", StartLine: 42}}
	if got := supersededSignals(near, inv); len(got) != 1 || got[0] == "" {
		t.Fatalf("a rule near the signal replaces it: %v", got)
	}
}

// Replaced signals do not decide a control: with nothing else left it
// passes, with another signal left that signal decides, and the reason
// says how many were replaced.
func TestRedecideWithoutSupersededSignals(t *testing.T) {
	heuristic := model.Signal{RuleID: "code.sql-concat", ControlID: "D-003", Collector: "builtin-code", Severity: model.SevHigh, Confidence: model.Hypothesis}
	other := model.Signal{RuleID: "code.sql-unsafe-raw", ControlID: "D-002", Collector: "builtin-code", Severity: model.SevHigh, Confidence: model.Confirmed}
	sigs := []model.Signal{heuristic, heuristic, other}
	results := map[string]*model.ControlResult{
		"D-003": {ID: "D-003", Status: model.StatusSuspected},
		"D-002": {ID: "D-002", Status: model.StatusFail},
	}
	decided := map[string]signalRange{"D-003": {from: 0, to: 3, detail: "d"}, "D-002": {from: 0, to: 3, detail: "d"}}
	redecide(results, sigs, decided, nil, map[int]string{0: "x", 1: "x"})
	if r := results["D-003"]; r.Status != model.StatusPass || !strings.Contains(r.Reason, "2 built-in heuristic signal(s) replaced") {
		t.Errorf("D-003 = %s %q", r.Status, r.Reason)
	}
	if r := results["D-002"]; r.Status != model.StatusFail {
		t.Errorf("D-002 = %s %q, its own signal must still decide it", r.Status, r.Reason)
	}

	results["D-003"].Status = model.StatusSuspected
	redecide(results, sigs, decided, nil, nil)
	if results["D-003"].Status != model.StatusSuspected {
		t.Error("without a completed semgrep run nothing is replaced")
	}
}

// In the Python files the taint engine analyzed, the bundled rules it
// replaces do not count; elsewhere they do, as do rules it does not
// replace, rules a project adds and the built-in heuristics.
func TestSupersededInTaintFiles(t *testing.T) {
	inv := &inventory.Inventory{Files: []*inventory.File{
		{Path: "app.js", Lang: "javascript"},
		{Path: "app.py", Lang: "python"},
		{Path: "tests/test_app.py", Lang: "python"},
	}}
	sigs := []model.Signal{
		{Collector: "semgrep", RuleID: "semgrep.pandaward-py-xss", File: "app.py"},            // 0 replaced
		{Collector: "semgrep", RuleID: "semgrep.pandaward-py-tls-verify-off", File: "app.py"}, // 1 kept
		{Collector: "semgrep", RuleID: "semgrep.my-own-rule", File: "app.py"},                 // 2 kept
		{Collector: "builtin-code", RuleID: "code.py-eval", File: "app.py"},                   // 3 kept: runs without Semgrep
		{Collector: "semgrep", RuleID: "semgrep.pandaward-py-xss", File: "tests/test_app.py"}, // 4 kept
		{Collector: "builtin-code", RuleID: "code.sql-concat", File: "app.js"},                // 5 kept
	}
	got := supersededInTaintFiles(sigs, inv, nil)
	if len(got) != 1 || got[0] == "" {
		t.Errorf("superseded %v", got)
	}
}
