package engine

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func rescan(t *testing.T, e *Engine) string {
	t.Helper()
	res, err := e.Scan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.AssessmentID
}

func rules(items []DeltaItem) map[string]bool {
	out := map[string]bool{}
	for _, it := range items {
		out[it.RuleID] = true
	}
	return out
}

func TestDeltaIsStableAcrossEquivalentReruns(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, first := scan(t, root)
	defer e.Close()
	b, c := rescan(t, e), rescan(t, e)
	d1, err := e.Diff(first.AssessmentID, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(d1.New)+len(d1.Reopened)+len(d1.Remediated)+len(d1.Stale)+len(d1.Waived) != 0 || d1.Unchanged == 0 {
		t.Fatalf("an unchanged rerun must show no changes: %+v", d1)
	}
	d2, _ := e.Diff(first.AssessmentID, c)
	d1.To, d2.To = "", ""
	if !reflect.DeepEqual(d1, d2) {
		t.Fatalf("equivalent reruns gave different deltas:\n%+v\n%+v", d1, d2)
	}
	again, _ := e.Diff(first.AssessmentID, b)
	again.To = ""
	if !reflect.DeepEqual(d1, again) {
		t.Fatal("the same comparison must be reproducible")
	}
	if _, err := e.Diff(b, first.AssessmentID); err == nil {
		t.Fatal("from must be older than to")
	}
}

func TestDeltaClassifiesChanges(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, first := scan(t, root)
	defer e.Close()

	// Fix the container: its finding is remediated because builtin-infra ran.
	original := "FROM node:latest\nCOPY . .\nCMD [\"node\",\"src/server.js\"]\n"
	testfixture.Write(t, root, "Dockerfile", "FROM node:20.11.1\nUSER node\nCOPY . .\nCMD [\"node\",\"src/server.js\"]\n")
	fixed := rescan(t, e)
	d, err := e.Diff(first.AssessmentID, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if !rules(d.Remediated)["infra.container-root"] || len(d.New) != 0 {
		t.Fatalf("expected the container finding to be remediated: %+v", d)
	}

	// Revert: the same finding comes back as reopened, not new.
	testfixture.Write(t, root, "Dockerfile", original)
	reverted := rescan(t, e)
	d, _ = e.Diff(fixed, reverted)
	if !rules(d.Reopened)["infra.container-root"] || rules(d.New)["infra.container-root"] {
		t.Fatalf("expected the container finding to be reopened: %+v", d)
	}

	// A new weakness is new; a finding whose collector did not run is stale.
	testfixture.Write(t, root, "src/extra.js", "const t = Math.random().toString(36); // session token\n")
	e.Cfg.Scan.Adapters = []string{"builtin-inventory", "builtin-secrets", "builtin-code", "builtin-cicd", "builtin-supply", "builtin-mobile"}
	partial := rescan(t, e)
	d, _ = e.Diff(reverted, partial)
	if !rules(d.New)["code.insecure-random"] {
		t.Errorf("expected a new insecure-random finding: %+v", d.New)
	}
	if !rules(d.Stale)["infra.container-root"] || rules(d.Remediated)["infra.container-root"] {
		t.Errorf("a finding whose collector did not run must be stale, not remediated: %+v", d)
	}

	// Waivers between two assessments are listed.
	fs, _ := e.St.Findings(e.ProjectID)
	var id string
	for _, f := range fs {
		if f.RuleID == "code.insecure-random" {
			id = f.ID
		}
	}
	time.Sleep(1100 * time.Millisecond) // event timestamps have second resolution
	if _, err := e.Triage(id, "false-positive", "reviewer", "test value, not a token", time.Time{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	waived := rescan(t, e)
	d, _ = e.Diff(partial, waived)
	if len(d.Waived) != 1 || d.Waived[0].FindingID != id {
		t.Errorf("expected %s to be listed as waived: %+v", id, d.Waived)
	}
}

func TestDeltaRequiresTrackedAssessments(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, first := scan(t, root)
	defer e.Close()
	second := rescan(t, e)
	if _, err := e.St.DB.Exec(`UPDATE assessments SET observed=0 WHERE id=?`, first.AssessmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Diff(first.AssessmentID, second); err == nil {
		t.Fatal("an assessment without observation tracking must not be compared")
	}
	if d, err := e.DeltaToPrevious(second); err != nil || d != nil {
		t.Fatalf("no tracked previous assessment means no delta: %v %v", d, err)
	}
}
