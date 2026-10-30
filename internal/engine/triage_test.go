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

func openIDs(t *testing.T, e *Engine, n int) []string {
	t.Helper()
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range fs {
		if f.Status.Active() && len(ids) < n {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) < n {
		t.Fatalf("fixture has %d open findings, need %d", len(ids), n)
	}
	return ids
}

func TestTriageBatchAppliesAll(t *testing.T) {
	e, _ := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	ids := openIDs(t, e, 2)
	out, err := e.TriageBatch([]TriageDecision{
		{FindingID: ids[0], Action: "false-positive", Note: "test fixture"},
		{FindingID: ids[1], Action: "confirm", Note: "reachable from the login route"},
	}, "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Status != model.FindingFalsePositive {
		t.Fatalf("unexpected result: %+v", out)
	}
	evs, err := e.St.Events(e.ProjectID, 10)
	if err != nil {
		t.Fatal(err)
	}
	logged := map[string]bool{}
	for _, ev := range evs {
		if strings.HasSuffix(ev.Reason, " by reviewer") {
			logged[ev.Entity] = true
		}
	}
	if !logged[ids[0]] || !logged[ids[1]] {
		t.Fatalf("every decision needs an audit event: %+v", evs)
	}
}

func TestTriageBatchRejectsWholeBatch(t *testing.T) {
	e, _ := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	ids := openIDs(t, e, 1)
	cases := map[string][]TriageDecision{
		"unknown id":     {{FindingID: ids[0], Action: "false-positive", Note: "x"}, {FindingID: "PW-9999", Action: "confirm", Note: "x"}},
		"unknown action": {{FindingID: ids[0], Action: "delete", Note: "x"}},
		"duplicate":      {{FindingID: ids[0], Action: "false-positive", Note: "x"}, {FindingID: ids[0], Action: "confirm", Note: "x"}},
		"missing note":   {{FindingID: ids[0], Action: "false-positive", Note: " "}},
		"bad expiry":     {{FindingID: ids[0], Action: "accept-risk", Note: "x", Expires: "soon"}},
	}
	for name, ds := range cases {
		if _, err := e.TriageBatch(ds, "reviewer"); err == nil {
			t.Errorf("%s: expected the batch to be rejected", name)
		}
	}
	f, _ := e.St.Finding(e.ProjectID, ids[0])
	if !f.Status.Active() {
		t.Fatalf("a rejected batch must not change anything, %s is %s", ids[0], f.Status)
	}
	if _, err := e.TriageBatch(nil, "reviewer"); err == nil {
		t.Error("an empty batch must be rejected")
	}
	if _, err := e.TriageBatch([]TriageDecision{{FindingID: ids[0], Action: "confirm", Note: "x"}}, ""); err == nil {
		t.Error("a reviewer name is required")
	}
}

func TestReadTriageDecisionsIsStrict(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.json")
	os.WriteFile(p, []byte(`[{"finding_id":"PW-0001","action":"confirm","note":"x","status":"CLOSED"}]`), 0o644)
	if _, err := ReadTriageDecisions(p); err == nil {
		t.Error("unknown fields must be rejected")
	}
	os.WriteFile(p, []byte(`[{"finding_id":"PW-0001","action":"confirm","note":"x"}]`), 0o644)
	if ds, err := ReadTriageDecisions(p); err != nil || len(ds) != 1 {
		t.Errorf("valid file: %v %v", ds, err)
	}
}

func TestRemediatedReviewFinding(t *testing.T) {
	e, _ := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	in := HypothesisInput{ControlID: "C-001", Title: "Invoice lookup lacks tenant filter", Severity: "high",
		File: "src/server.js", StartLine: 6, Rationale: "query uses only the id", Proposer: "identity-agent"}
	h, err := e.RecordHypothesis(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Triage(h.ID, "remediated", "Jane", "", time.Time{}); err == nil {
		t.Fatal("remediated without a note must be rejected")
	}
	f, err := e.Triage(h.ID, "remediated", "Jane", "fixed in PR 12", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != model.FindingRemediated || f.Confidence != model.StronglySupported || !strings.Contains(f.Note, "remediated] fixed in PR 12") {
		t.Fatalf("after remediated: %+v", f)
	}
	if _, err := e.Triage(h.ID, "remediated", "Jane", "again", time.Time{}); err == nil {
		t.Fatal("a remediated finding cannot be marked remediated again")
	}
	// A rescan does not touch it: no collector re-checks a reviewer finding.
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if g, _ := e.St.Finding(e.ProjectID, h.ID); g.Status != model.FindingRemediated {
		t.Fatalf("rescan changed a remediated review finding to %s", g.Status)
	}
	// The same hypothesis recorded again reopens it.
	r, err := e.RecordHypothesis(in)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != h.ID || r.Status != model.FindingReopened || len(r.EvidenceIDs) != 2 {
		t.Fatalf("repeat hypothesis: %+v", r)
	}
	// In a batch as well.
	out, err := e.TriageBatch([]TriageDecision{{FindingID: h.ID, Action: "remediated", Note: "fixed again in PR 13"}}, "Jane")
	if err != nil || out[0].Status != model.FindingRemediated {
		t.Fatalf("batch remediated: %+v, %v", out, err)
	}
}
