package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// sarifFixture writes a small project with one imported CodeQL result.
func sarifFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	testfixture.Write(t, root, "src/db.js", "const id = req.query.id;\ndb.query('SELECT * FROM t WHERE id=' + id);\n")
	doc := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "CodeQL", "semanticVersion": "2.19.0", "rules": []any{
			map[string]any{"id": "js/sql-injection", "properties": map[string]any{"tags": []string{"external/cwe/cwe-089"}, "security-severity": "8.8"}}}}},
		"results": []any{map[string]any{"ruleId": "js/sql-injection", "ruleIndex": 0, "message": map[string]any{"text": "Query built from " + testfixture.FakeStripe},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "src/db.js", "uriBaseId": "%SRCROOT%"},
				"region": map[string]any{"startLine": 2}}}}}},
	}}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	testfixture.Write(t, root, adapters.SARIFDir+"/codeql.sarif", string(b))
	return root
}

func TestSARIFImportFindingsAreStable(t *testing.T) {
	root := sarifFixture(t)
	e, res := scan(t, root)
	defer e.Close()
	if res.Status != "COMPLETE" {
		t.Fatalf("scan %s: %v", res.Status, res.Errors)
	}
	var run model.Run
	for _, r := range res.Runs {
		if r.Adapter == adapters.SARIFImport {
			run = r
		}
	}
	if run.ExitClass != model.ExitOK || !strings.Contains(run.ToolVersion, "CodeQL 2.19.0") {
		t.Fatalf("sarif-import run: %+v", run)
	}
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	var got []model.Finding
	for _, f := range fs {
		if f.Collector == adapters.SARIFImport {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want 1 imported finding, got %d", len(got))
	}
	f := got[0]
	if f.RuleID != "sarif.codeql.js-sql-injection" || f.ControlID != "R-002" || f.Confidence != model.Hypothesis || f.Severity != model.SevHigh ||
		f.CWE != "CWE-89" || f.File != "src/db.js" || f.StartLine != 2 || strings.Contains(f.Message, testfixture.FakeStripe) {
		t.Errorf("unexpected finding: %+v", f)
	}
	if c := controlMap(t, e, res.AssessmentID)["R-002"]; c.Status != model.StatusSuspected {
		t.Errorf("R-002: %s (%s)", c.Status, c.Reason)
	}

	res2, err := e.Scan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res2.New != 0 || res2.Remediated != 0 {
		t.Errorf("repeated scan changed findings: new %d, remediated %d", res2.New, res2.Remediated)
	}
	again, _ := e.St.FindingByFingerprint(e.ProjectID, f.Fingerprint)
	if again == nil || again.ID != f.ID || again.Status != model.FindingOpen {
		t.Errorf("fingerprint not stable across scans: %+v", again)
	}
	res3, err := e.Retest(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res3.Runs {
		if r.Adapter == adapters.SARIFImport && r.ExitClass != model.ExitOK {
			t.Errorf("sarif-import must re-run on retest, got %s", r.ExitClass)
		}
	}
}

func TestSARIFImportMalformedIsError(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/a.js", "x\n")
	testfixture.Write(t, root, adapters.SARIFDir+"/bad.sarif", "not json")
	e, res := scan(t, root)
	defer e.Close()
	if c := controlMap(t, e, res.AssessmentID)["R-002"]; c.Status != model.StatusError {
		t.Errorf("R-002: %s (%s), want ERROR", c.Status, c.Reason)
	}
	if res.Status != "INCOMPLETE" {
		t.Errorf("scan status %s", res.Status)
	}
}

func TestSARIFImportNotApplicableWithoutInputs(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/a.js", "x\n")
	e, res := scan(t, root)
	defer e.Close()
	if c := controlMap(t, e, res.AssessmentID)["R-002"]; c.Status != model.StatusNotApplicable {
		t.Errorf("R-002: %s (%s)", c.Status, c.Reason)
	}
	for _, r := range res.Runs {
		if r.Adapter == adapters.SARIFImport {
			t.Errorf("sarif-import ran without inputs")
		}
	}
}
