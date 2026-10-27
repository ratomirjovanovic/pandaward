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
