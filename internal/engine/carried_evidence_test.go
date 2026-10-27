package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/evidence"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
)

// retestDockerfile edits only the Dockerfile and runs a targeted retest, so
// builtin-code decisions and their evidence are carried over.
func retestDockerfile(t *testing.T, e *Engine, root string) *ScanResult {
	t.Helper()
	testfixture.Write(t, root, "Dockerfile", "FROM node:20.11.1\nUSER node\nCMD [\"node\",\"src/server.js\"]\n")
	inv, err := e.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := e.ChangedSinceLast(inv)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Retest(context.Background(), nil, changed)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestCarriedEvidenceIsVerified(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, first := scan(t, root)
	defer e.Close()
	carriedID := controlMap(t, e, first.AssessmentID)["D-001"].EvidenceIDs[0]

	res := retestDockerfile(t, e, root)
	cm := controlMap(t, e, res.AssessmentID)
	if cm["D-001"].EvidenceIDs[0] != carriedID {
		t.Fatal("D-001 evidence must be carried over")
	}
	if r := cm["R-001"]; r.Status != model.StatusPass || !strings.Contains(r.Reason, "carried from "+first.AssessmentID) {
		t.Fatalf("R-001 must verify carried evidence: %s %s", r.Status, r.Reason)
	}
	cs, _ := e.St.Controls(res.AssessmentID)
	rows, missing, err := evidence.Collect(e.St, res.AssessmentID, evidence.Referenced(cs))
	if err != nil || len(missing) != 0 {
		t.Fatal(missing, err)
	}
	listed := false
	for _, r := range rows {
		listed = listed || r.ID == carriedID
	}
	if !listed {
		t.Fatal("carried evidence must be part of the assessment's evidence set")
	}
}

func TestTamperedCarriedEvidenceFailsR001(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, first := scan(t, root)
	defer e.Close()
	carriedID := controlMap(t, e, first.AssessmentID)["D-001"].EvidenceIDs[0]
	row, err := e.St.Evidence(carriedID)
	if err != nil || row == nil {
		t.Fatal(row, err)
	}
	p := filepath.Join(evidence.Dir(e.Private()), row.Path)
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append(b, ' '), 0o600); err != nil {
		t.Fatal(err)
	}

	res := retestDockerfile(t, e, root)
	r := controlMap(t, e, res.AssessmentID)["R-001"]
	if r.Status != model.StatusFail || !strings.Contains(r.Reason, carriedID) {
		t.Fatalf("tampered carried evidence must fail R-001: %s %s", r.Status, r.Reason)
	}
}
