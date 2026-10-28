package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
)

// staleView returns the stale view of the latest assessment by ID.
func staleView(t *testing.T, e *Engine) (map[string]model.ControlResult, map[string]model.Edge) {
	t.Helper()
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil || a == nil {
		t.Fatal(a, err)
	}
	cs, _ := e.St.Controls(a.ID)
	es, _ := e.St.Edges(a.ID)
	cs, es, _, err = e.StaleView(a.ID, cs, es)
	if err != nil {
		t.Fatal(err)
	}
	cm, em := map[string]model.ControlResult{}, map[string]model.Edge{}
	for _, c := range cs {
		cm[c.ID] = c
	}
	for _, x := range es {
		em[x.ID] = x
	}
	return cm, em
}

func markChanged(t *testing.T, e *Engine, rel ...string) {
	t.Helper()
	for _, r := range rel {
		if ok, err := e.MarkChanged(r); err != nil || !ok {
			t.Fatal(r, ok, err)
		}
	}
}

func wantStatus(t *testing.T, cm map[string]model.ControlResult, want map[string]model.Status) {
	t.Helper()
	for id, st := range want {
		if cm[id].Status != st {
			t.Errorf("%s: got %s (%s), want %s", id, cm[id].Status, cm[id].Reason, st)
		}
	}
}

func TestEditInvalidatesOnlyDependentControls(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, res := scan(t, root)
	defer e.Close()
	before := res.Coverage.Decisive
	markChanged(t, e, "src/server.js")
	cm, em := staleView(t, e)
	wantStatus(t, cm, map[string]model.Status{
		"D-001": model.StatusStale, "G-001": model.StatusStale, "H-001": model.StatusStale,
		"N-001": model.StatusFail, "J-001": model.StatusFail, "K-001": model.StatusFail,
		// Undecided controls stay undecided rather than STALE.
		"C-001": model.StatusBlocked, "F-001": model.StatusBlocked,
	})
	if em["DG1"].Status != model.StatusStale {
		t.Errorf("edge DG1 depends on G-001 and must be STALE, got %s", em["DG1"].Status)
	}
	if em["IN1"].Status != model.StatusFail {
		t.Errorf("edge IN1 depends only on N-001 and must keep FAIL, got %s", em["IN1"].Status)
	}
	s, err := e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.Coverage.Decisive == 0 || s.Coverage.Decisive >= before {
		t.Fatalf("coverage must drop only for stale controls: before %d, now %d", before, s.Coverage.Decisive)
	}
	if len(s.StaleControls) == 0 {
		t.Fatal("status must list stale controls")
	}
}

func TestDeleteRenameAndNewFiles(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	defer e.Close()

	// Each step is undone on disk before the next one, because changed
	// content is detected by hash even without the hook record.
	dockerfile, _ := os.ReadFile(filepath.Join(root, "Dockerfile"))

	// Delete: the Dockerfile is known, so only adapters that read it go stale.
	os.Remove(filepath.Join(root, "Dockerfile"))
	markChanged(t, e, "Dockerfile")
	cm, _ := staleView(t, e)
	wantStatus(t, cm, map[string]model.Status{"J-001": model.StatusStale, "D-001": model.StatusFail, "N-001": model.StatusFail})
	e.St.ClearStale(e.ProjectID)
	os.WriteFile(filepath.Join(root, "Dockerfile"), dockerfile, 0o644)

	// Rename: the old path is known, the new path is not.
	wf := filepath.Join(root, ".github", "workflows")
	if err := os.Rename(filepath.Join(wf, "ci.yml"), filepath.Join(wf, "build.yml")); err != nil {
		t.Fatal(err)
	}
	markChanged(t, e, ".github/workflows/ci.yml", ".github/workflows/build.yml")
	cm, _ = staleView(t, e)
	wantStatus(t, cm, map[string]model.Status{"N-001": model.StatusStale, "N-003": model.StatusStale, "D-001": model.StatusFail, "K-001": model.StatusFail, "E-003": model.StatusFail})
	e.St.ClearStale(e.ProjectID)
	os.Rename(filepath.Join(wf, "build.yml"), filepath.Join(wf, "ci.yml"))

	// New file: an iOS plist can make the iOS domain applicable.
	testfixture.Write(t, root, "ios/App/Info.plist", "<plist><dict></dict></plist>\n")
	markChanged(t, e, "ios/App/Info.plist")
	cm, _ = staleView(t, e)
	wantStatus(t, cm, map[string]model.Status{"L-001": model.StatusStale, "D-001": model.StatusFail, "J-001": model.StatusFail, "N-001": model.StatusFail})
}

func TestChangesOutsideClaudeAreDetected(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	defer e.Close()
	// No hook records: edit, delete and add files directly on disk.
	testfixture.Write(t, root, "src/server.js", "module.exports = {};\n")
	os.Remove(filepath.Join(root, "Dockerfile"))
	testfixture.Write(t, root, "ios/App/Info.plist", "<plist><dict></dict></plist>\n")
	s, err := e.Status()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Dockerfile (deleted)", "ios/App/Info.plist", "src/server.js"}
	if strings.Join(s.ChangedOutside, ",") != strings.Join(want, ",") || strings.Join(s.StaleFiles, ",") != strings.Join(want, ",") {
		t.Fatalf("outside changes: got %v / %v, want %v", s.ChangedOutside, s.StaleFiles, want)
	}
	cm, _ := staleView(t, e)
	wantStatus(t, cm, map[string]model.Status{"D-001": model.StatusStale, "J-001": model.StatusStale, "L-001": model.StatusStale, "N-001": model.StatusFail, "I-001": model.StatusFail})

	// A path the hook already recorded is not reported a second time.
	markChanged(t, e, "src/server.js")
	s, _ = e.Status()
	if len(s.ChangedOutside) != 2 || len(s.StaleFiles) != 3 {
		t.Fatalf("hook-recorded file must not be duplicated: %v / %v", s.ChangedOutside, s.StaleFiles)
	}
	// Status only reads: nothing is added to the ledger's stale list.
	if hooked, _ := e.St.StaleFiles(e.ProjectID); len(hooked) != 1 {
		t.Fatalf("status must not write stale files: %v", hooked)
	}
}

func TestHashBudgetSkipsCheck(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	defer e.Close()
	testfixture.Write(t, root, "src/server.js", "module.exports = {};\n")
	e.HashBudget = time.Nanosecond
	s, err := e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.ChangeCheck == "" || len(s.ChangedOutside) != 0 {
		t.Fatalf("an exhausted budget must skip the check and say so: %q %v", s.ChangeCheck, s.ChangedOutside)
	}
}

func TestRetestChangedCarriesUnaffectedAdapters(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, first := scan(t, root)
	defer e.Close()
	before := controlMap(t, e, first.AssessmentID)
	testfixture.Write(t, root, "Dockerfile", "FROM node:20.11.1\nUSER node\nCOPY . .\nCMD [\"node\",\"src/server.js\"]\n")
	markChanged(t, e, "Dockerfile")
	inv, err := e.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := e.ChangedSinceLast(inv)
	if err != nil || len(changed) != 1 {
		t.Fatalf("changed: %v %v", changed, err)
	}
	res, err := e.Retest(context.Background(), nil, changed)
	if err != nil {
		t.Fatal(err)
	}
	runs := map[string]string{}
	for _, r := range res.Runs {
		runs[r.Adapter] = r.ExitClass
	}
	if runs["builtin-infra"] != model.ExitOK || runs["builtin-code"] != model.ExitCarried || runs["builtin-cicd"] != model.ExitCarried {
		t.Fatalf("unexpected runs: %v", runs)
	}
	cm := controlMap(t, e, res.AssessmentID)
	if cm["J-001"].Status != model.StatusPass {
		t.Errorf("J-001 must be re-decided: got %s (%s)", cm["J-001"].Status, cm["J-001"].Reason)
	}
	for _, id := range []string{"D-001", "G-001", "N-001"} {
		if cm[id].Status != before[id].Status || len(cm[id].EvidenceIDs) != len(before[id].EvidenceIDs) {
			t.Errorf("%s must be carried over: got %s, was %s", id, cm[id].Status, before[id].Status)
		}
	}
	if res.Remediated < 1 {
		t.Errorf("fixed container finding must be remediated, got %d", res.Remediated)
	}
	fs, _ := e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if f.Collector == "builtin-code" && (f.Status == model.FindingRemediated || f.Stale) {
			t.Errorf("carried finding %s changed: %s stale=%v", f.ID, f.Status, f.Stale)
		}
	}
	if s, _ := e.Status(); len(s.StaleFiles) != 0 || len(s.StaleControls) != 0 {
		t.Fatalf("retest must clear stale state: %+v", s)
	}
}
