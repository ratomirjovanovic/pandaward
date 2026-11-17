package engine

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func kindsOf(r *VerifyResult) string {
	var k []string
	for _, m := range r.Mismatches {
		k = append(k, m.Kind+":"+m.Control)
	}
	return strings.Join(k, ",")
}

// controlWith returns a control of the assessment in the given status.
func controlWith(t *testing.T, e *Engine, asmt string, want model.Status) model.ControlResult {
	t.Helper()
	for _, c := range controlMap(t, e, asmt) {
		if c.Status == want {
			return c
		}
	}
	t.Skipf("the fixture has no %s control", want)
	return model.ControlResult{}
}

func TestVerifyReportAgainstTheLedger(t *testing.T) {
	e, res := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	fail := controlWith(t, e, res.AssessmentID, model.StatusFail)
	blocked := controlWith(t, e, res.AssessmentID, model.StatusBlocked)

	// An honest report passes.
	honest := fail.ID + ": FAIL, see the finding.\n" + blocked.ID + ": BLOCKED, not decided.\n"
	r, err := e.VerifyReport(honest, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Unsupported || r.Claims != 2 || r.Assessment != res.AssessmentID {
		t.Fatalf("an honest report must verify: %+v", r)
	}

	// PASS where the ledger has FAIL or BLOCKED is false assurance.
	lie := fail.ID + ": PASS\n" + blocked.ID + ": PASS\n"
	r, _ = e.VerifyReport(lie, false)
	if !r.Unsupported || !strings.Contains(kindsOf(r), "unsupported_pass:"+fail.ID) || !strings.Contains(kindsOf(r), "unsupported_pass:"+blocked.ID) {
		t.Fatalf("%+v", r)
	}

	// A report about one control is not a full review and need not name every open finding.
	r, _ = e.VerifyReport(blocked.ID+": BLOCKED\n", false)
	if r.Unsupported {
		t.Fatalf("a partial report is not held to a full review: %+v", r)
	}
	// A full review may not leave an open finding out.
	r, _ = e.VerifyReport(blocked.ID+": BLOCKED\n", true)
	if !r.Unsupported || !strings.Contains(kindsOf(r), "hidden:"+fail.ID) {
		t.Fatalf("%+v", r)
	}

	// An all-clear claim is never supported while controls are not PASS.
	r, _ = e.VerifyReport("All controls passed.\n", false)
	if !r.Unsupported || !strings.Contains(kindsOf(r), "blanket:") || r.Note == "" {
		t.Fatalf("%+v", r)
	}

	// BLOCKED and INCONCLUSIVE are both undecided: not a mismatch.
	r, _ = e.VerifyReport(fail.ID+": FAIL\n"+blocked.ID+": INCONCLUSIVE\n", false)
	if r.Unsupported || len(r.Mismatches) != 0 {
		t.Fatalf("%+v", r)
	}

	// Caution is listed and never counts as false assurance.
	r, _ = e.VerifyReport(fail.ID+": FAIL\n"+blocked.ID+": FAIL\n", false)
	if r.Unsupported || !strings.Contains(kindsOf(r), "overclaimed:"+blocked.ID) {
		t.Fatalf("%+v", r)
	}

	// A report with no claims and no all-clear says nothing that can be false.
	r, _ = e.VerifyReport("I fixed the typo in the readme.\n", false)
	if r.Unsupported || len(r.Mismatches) != 0 || r.Claims != 0 {
		t.Fatalf("%+v", r)
	}

	// An evidence hash the ledger never recorded for that control is fabricated.
	r, _ = e.VerifyReport(fail.ID+": FAIL sha256: "+strings.Repeat("a", 64)+"\n", false)
	if !r.Unsupported || !strings.Contains(kindsOf(r), "fabricated_hash:"+fail.ID) {
		t.Fatalf("%+v", r)
	}
}

func TestVerifyReportNeedsAnAssessment(t *testing.T) {
	e, _ := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	e2 := *e
	e2.ProjectID = "no-such-project"
	if _, err := e2.VerifyReport("A-001: PASS", false); err == nil || !strings.Contains(err.Error(), "no assessment") {
		t.Fatalf("%v", err)
	}
}

// A hash that the ledger did record for the control is accepted.
func TestVerifyReportAcceptsARecordedHash(t *testing.T) {
	e, res := scan(t, testfixture.VulnerableRepo(t))
	defer e.Close()
	cs := controlMap(t, e, res.AssessmentID)
	ev, err := e.St.EvidenceFor(res.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	hashOf := map[string]string{}
	for _, r := range ev {
		hashOf[r.ID] = r.SHA256
	}
	for _, c := range cs {
		for _, id := range c.EvidenceIDs {
			if h := hashOf[id]; h != "" && (c.Status == model.StatusFail || c.Status == model.StatusPass) {
				r, _ := e.VerifyReport(c.ID+": "+string(c.Status)+" sha256: "+h+"\n", false)
				if strings.Contains(kindsOf(r), "fabricated_hash") {
					t.Fatalf("a recorded hash must be accepted: %+v", r)
				}
				return
			}
		}
	}
	t.Skip("the fixture records no evidence hash on a decided control")
}
