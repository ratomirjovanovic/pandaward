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
	got := supersededSignals(sigs, inv)
	if len(got) != 2 || got[0] != "semgrep.pandaward-java-sql-injection" || got[1] != "semgrep.pandaward-js-sql-injection" {
		t.Fatalf("superseded = %v, want signals 0 and 1", got)
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
