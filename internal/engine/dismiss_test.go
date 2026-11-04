package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// findingsOf returns the findings of one control in the ledger.
func findingsOf(t *testing.T, e *Engine, cid string) []model.Finding {
	t.Helper()
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	var out []model.Finding
	for _, f := range fs {
		if f.ControlID == cid {
			out = append(out, f)
		}
	}
	return out
}

func dismiss(t *testing.T, e *Engine, fs ...model.Finding) {
	t.Helper()
	for _, f := range fs {
		if _, err := e.Triage(f.ID, "false-positive", "Jane", "route is declared in the gateway", time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
}

func rescanControls(t *testing.T, e *Engine) map[string]model.ControlResult {
	t.Helper()
	res, err := e.Scan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return controlMap(t, e, res.AssessmentID)
}

// The fixture has three undeclared routes, all heuristic signals of A-003.
func TestDismissedSignalsPassControl(t *testing.T) {
	e, res := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	if c := controlMap(t, e, res.AssessmentID)["A-003"]; c.Status != model.StatusSuspected {
		t.Fatalf("A-003 before triage: %s (%s)", c.Status, c.Reason)
	}
	fs := findingsOf(t, e, "A-003")
	if len(fs) != 3 {
		t.Fatalf("want 3 A-003 findings, got %d", len(fs))
	}
	dismiss(t, e, fs...)
	// Triage alone changes no control: the last assessment stays as it was.
	if c := controlMap(t, e, res.AssessmentID)["A-003"]; c.Status != model.StatusSuspected {
		t.Fatalf("triage changed the stored control to %s", c.Status)
	}
	c := rescanControls(t, e)["A-003"]
	want := "check completed; 3 signal(s) dismissed as false positive by Jane; PASS applies to this check only"
	if c.Status != model.StatusPass || c.Reason != want {
		t.Fatalf("A-003 after rescan: %s (%s)", c.Status, c.Reason)
	}
	for _, f := range findingsOf(t, e, "A-003") {
		if f.Status != model.FindingFalsePositive {
			t.Errorf("%s must stay FALSE_POSITIVE and listed, got %s", f.ID, f.Status)
		}
	}
	if len(c.EvidenceIDs) != 3 {
		t.Errorf("dismissed signals keep their evidence on the control, got %d", len(c.EvidenceIDs))
	}

	// The code of one dismissed line changes: a new signal that counts again.
	p := filepath.Join(e.Root, "src", "server.js")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(b), "applyPayment(req.body);", "applyPayment(req.body); audit(req);", 1)
	if changed == string(b) {
		t.Fatal("fixture line not found")
	}
	if err := os.WriteFile(p, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	c = rescanControls(t, e)["A-003"]
	if c.Status != model.StatusSuspected || !strings.Contains(c.Reason, "1 heuristic signal(s)") || !strings.Contains(c.Reason, "2 signal(s) dismissed as false positive by Jane") {
		t.Fatalf("A-003 after the code changed: %s (%s)", c.Status, c.Reason)
	}
}

func TestPartlyDismissedStaysSuspected(t *testing.T) {
	e, _ := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	dismiss(t, e, findingsOf(t, e, "A-003")[0])
	c := rescanControls(t, e)["A-003"]
	if c.Status != model.StatusSuspected || c.Reason != "2 heuristic signal(s) need review; not confirmed; 1 signal(s) dismissed as false positive by Jane" {
		t.Fatalf("A-003: %s (%s)", c.Status, c.Reason)
	}
}

func TestRiskAcceptedStillCounts(t *testing.T) {
	e, _ := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	fs := findingsOf(t, e, "G-001")
	if len(fs) != 1 {
		t.Fatalf("want one G-001 finding, got %d", len(fs))
	}
	if _, err := e.Triage(fs[0].ID, "accept-risk", "Jane", "fixed next sprint", time.Now().AddDate(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	if c := rescanControls(t, e)["G-001"]; c.Status != model.StatusSuspected || strings.Contains(c.Reason, "dismissed") {
		t.Fatalf("G-001 with accepted risk: %s (%s)", c.Status, c.Reason)
	}
}

// A signal without a code snippet keeps its fingerprint when the code
// changes, so a false positive mark cannot be bound to the reviewed code.
func TestSnippetlessSignalStillCounts(t *testing.T) {
	e, _ := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	fs := findingsOf(t, e, "N-004")
	if len(fs) != 1 {
		t.Fatalf("want one N-004 finding, got %d", len(fs))
	}
	dismiss(t, e, fs[0])
	if c := rescanControls(t, e)["N-004"]; c.Status != model.StatusFail {
		t.Fatalf("N-004: %s (%s)", c.Status, c.Reason)
	}
	if line, err := e.RescanHint([]model.Finding{*mustFinding(t, e, fs[0].ID)}); err != nil || line != "" {
		t.Fatalf("no rescan hint for a signal a scan cannot dismiss: %q %v", line, err)
	}
}

func mustFinding(t *testing.T, e *Engine, id string) *model.Finding {
	t.Helper()
	f, err := e.St.Finding(e.ProjectID, id)
	if err != nil || f == nil {
		t.Fatalf("finding %s: %v", id, err)
	}
	return f
}

func TestRescanHint(t *testing.T) {
	e, res := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	fs := findingsOf(t, e, "A-003")
	dismiss(t, e, fs[0])
	if line, err := e.RescanHint([]model.Finding{*mustFinding(t, e, fs[0].ID)}); err != nil || line != "" {
		t.Fatalf("other signals remain, no hint expected: %q %v", line, err)
	}
	dismiss(t, e, fs[1:]...)
	var done []model.Finding
	for _, f := range fs {
		done = append(done, *mustFinding(t, e, f.ID))
	}
	line, err := e.RescanHint(done)
	want := "Every signal of A-003 in " + res.AssessmentID + " is now dismissed as false positive; the status changes only when a scan decides it again: pandaward retest"
	if err != nil || line != want {
		t.Fatalf("hint: %q %v", line, err)
	}
}

func TestDismissedSignalsNeedAPerson(t *testing.T) {
	sigs := []model.Signal{
		{RuleID: "r", ControlID: "D-001", File: "a.js", Snippet: "eval(x)", Collector: "c"},
		{RuleID: "r", ControlID: "D-001", File: "b.js", Snippet: "eval(y)", Collector: "c"},
		{RuleID: "r", ControlID: "D-001", File: "c.js", Collector: "c"},
	}
	ids := assignment{FP: []string{"fa", "fb", "fc"}, Moved: map[int]model.Finding{}}
	ledger := []model.Finding{
		{ID: "PW-1", Fingerprint: "fa", RuleID: "r", ControlID: "D-001", Status: model.FindingFalsePositive, Reviewer: "Jane"},
		{ID: "PW-2", Fingerprint: "fb", RuleID: "r", ControlID: "D-001", Status: model.FindingFalsePositive},
		{ID: "PW-3", Fingerprint: "fc", RuleID: "r", ControlID: "D-001", Status: model.FindingFalsePositive, Reviewer: "Jane"},
	}
	gone := dismissedSignals(sigs, ids, ledger)
	if _, ok := gone[0]; !ok || len(gone) != 1 {
		t.Fatalf("only the signal a named person dismissed, with a snippet, is dismissed: %+v", gone)
	}
	ledger[0].Status = model.FindingRiskAccepted
	if gone := dismissedSignals(sigs, ids, ledger); len(gone) != 0 {
		t.Fatalf("accepted risk is not a dismissal: %+v", gone)
	}
}

func TestDismissedForeignSignalDoesNotRaise(t *testing.T) {
	results := map[string]*model.ControlResult{
		"D-001": {ID: "D-001", Status: model.StatusPass, Reason: "check completed with no signal (x); PASS applies to this check only"},
		"D-003": {ID: "D-003", Status: model.StatusPass, Reason: "clean"},
	}
	sigs := []model.Signal{
		{ControlID: "D-001", Collector: "semgrep", Severity: model.SevHigh, Confidence: model.Hypothesis},
		{ControlID: "D-003", Collector: "semgrep", Severity: model.SevHigh, Confidence: model.Hypothesis},
		{ControlID: "D-003", Collector: "semgrep", Severity: model.SevHigh, Confidence: model.Hypothesis},
	}
	gone := map[int]model.Finding{0: {Reviewer: "Jane"}, 1: {Reviewer: "Jane"}}
	raise(results, sigs, []int{0, 1, 2}, gone)
	if r := results["D-001"]; r.Status != model.StatusPass || !strings.HasSuffix(r.Reason, "; 1 signal(s) dismissed as false positive by Jane from another collector") {
		t.Errorf("dismissed foreign signal must not raise D-001: %s (%s)", r.Status, r.Reason)
	}
	if r := results["D-003"]; r.Status != model.StatusSuspected {
		t.Errorf("the remaining foreign signal still raises D-003: %s (%s)", r.Status, r.Reason)
	}
}
