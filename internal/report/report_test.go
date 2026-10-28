package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/engine"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
)

func TestReportsAreRedactedAndValid(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Cfg.Scan.Adapters = []string{"builtin-inventory", "builtin-secrets", "builtin-code", "builtin-cicd", "builtin-infra", "builtin-supply", "builtin-mobile"}
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	r, err := Build(e)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := Write(r, DefaultDir(root), []string{"html", "markdown", "json", "sarif", "csv"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		b, _ := os.ReadFile(p)
		switch filepath.Ext(p) {
		case ".json", ".sarif":
			var v map[string]any
			if err := json.Unmarshal(b, &v); err != nil {
				t.Errorf("%s is not valid JSON: %v", p, err)
			}
		case ".html", ".md":
			if !strings.Contains(string(b), "Not a certification") {
				t.Errorf("%s lacks the attestation boundary", p)
			}
		}
	}
	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []any `json:"results"`
		} `json:"runs"`
	}
	b, _ := os.ReadFile(paths[3])
	json.Unmarshal(b, &sarif)
	if sarif.Version != "2.1.0" || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) == 0 {
		t.Errorf("unexpected SARIF: %+v", sarif)
	}
	e.St.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	filepath.Walk(filepath.Join(root, ".pensec"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, s := range []string{testfixture.FakeStripe, testfixture.FakeGitHub} {
			if strings.Contains(string(b), s) {
				t.Errorf("secret leaked into %s", p)
			}
		}
		return nil
	})
}

// Imported SARIF results reach every report format as unconfirmed findings,
// and PenSec's own SARIF report is never imported back.
func TestImportedSARIFInReports(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/db.js", "const id = req.query.id;\ndb.query('SELECT * FROM t WHERE id=' + id);\n")
	testfixture.Write(t, root, ".pensec/sarif/codeql.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","semanticVersion":"2.19.0"}},
	 "results":[{"ruleId":"js/sql-injection","level":"error","message":{"text":"Query built from user input"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.js"},"region":{"startLine":2}}}]}]}]}`)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Cfg.Scan.Adapters = []string{"builtin-inventory", "builtin-secrets", "builtin-code"}
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	r, err := Build(e)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range r.Suspected() {
		found = found || f.RuleID == "sarif.codeql.js-sql-injection"
	}
	if !found {
		t.Fatal("imported result missing from suspected findings")
	}
	paths, err := Write(r, DefaultDir(root), []string{"html", "markdown", "json", "sarif"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		b, _ := os.ReadFile(p)
		want := "sarif.codeql.js-sql-injection"
		if ext := filepath.Ext(p); ext == ".html" || ext == ".md" {
			want = "CodeQL: js/sql-injection"
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not list the imported result", filepath.Base(p))
		}
	}
	own, _ := os.ReadFile(paths[3])
	testfixture.Write(t, root, ".pensec/sarif/pensec.sarif", string(own))
	res, err := e.Scan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.New != 0 || res.Status != "COMPLETE" {
		t.Errorf("re-importing PenSec's own report: %d new, %s %v", res.New, res.Status, res.Errors)
	}
}
